"""
app/services/challenges.py — Payee Change Cases & Keyed HMAC Challenge Protocol
"""

import datetime
import hashlib
import hmac
import secrets
import uuid
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from app.config import SECRET_KEY
from app.models import PayeeChangeCase, VerificationChallenge, Vendor, VendorVersion, utcnow
from app.services.audit import record_audit_event
from app.services.exceptions import (
    ExpiredChallengeError,
    InvalidChallengeError,
    InvalidStateTransitionError,
    MaxAttemptsExceededError,
    SecurityViolationError,
    VendorFrozenError,
)
from app.services.vendor_registry import check_vendor_active, freeze_vendor, get_vendor

CHALLENGE_DEFAULT_EXPIRY_SECONDS = 900  # 15 minutes
MAX_VERIFICATION_ATTEMPTS = 3


def to_naive_utc(dt: datetime.datetime) -> datetime.datetime:
    """Normalize datetime to naive UTC for consistent SQLite comparisons."""
    if dt.tzinfo is not None:
        return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt


def compute_challenge_token_hmac(
    challenge_id: str,
    case_id: str,
    proposed_recipient: str,
    token: str,
) -> str:
    """
    Compute cryptographic HMAC-SHA256 of verification token.
    Binds the token to the exact challenge ID, case ID, proposed recipient,
    and server-side SECRET_KEY held strictly outside the database.
    """
    message = f"{challenge_id}:{case_id}:{proposed_recipient.strip().lower()}:{token.strip()}".encode("utf-8")
    return hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()


def compute_candidate_digest(
    case_id: str,
    vendor_id: str,
    base_version_id: str,
    proposed_recipient: str,
) -> str:
    """Compute bound digest linking the case, vendor, baseline version, and candidate recipient."""
    raw = f"{case_id}:{vendor_id}:{base_version_id}:{proposed_recipient.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_payee_change_case(
    session: Session,
    vendor_id: str,
    proposed_recipient: Optional[str],
    source_type: str,
    source_reference: str,
    requester_id: str,
    expires_in_hours: int = 48,
    case_type: str = "RECIPIENT_CHANGE_PROPOSAL",
) -> PayeeChangeCase:
    """
    Creates a new payee change or manual extraction review case.
    A proposed recipient change enters the HELD state immediately.
    It can NEVER authorize or activate a change on its own.
    
    If case_type == "MANUAL_EXTRACTION_REVIEW", proposed_recipient MUST be None or empty.
    If case_type == "RECIPIENT_CHANGE_PROPOSAL", proposed_recipient MUST be a validated email address.
    """
    from app.models import validate_paypal_recipient_email
    from app.services.exceptions import SecurityViolationError

    vendor = get_vendor(session, vendor_id)
    check_vendor_active(vendor)

    active_version = session.query(VendorVersion).filter_by(id=vendor.active_version_id).first()
    if not active_version:
        raise ValueError(f"Vendor '{vendor_id}' has no active version.")

    clean_proposed: Optional[str] = None
    if case_type == "MANUAL_EXTRACTION_REVIEW":
        clean_proposed = None
    else:
        case_type = "RECIPIENT_CHANGE_PROPOSAL"
        if not proposed_recipient:
            raise SecurityViolationError("Cannot create a RECIPIENT_CHANGE_PROPOSAL case without an explicit recipient.")
        clean_proposed = validate_paypal_recipient_email(proposed_recipient)
        # If requested recipient is identical to active version, no change case needed
        if clean_proposed == active_version.paypal_recipient.lower():
            raise ValueError("Proposed recipient matches existing active vendor recipient.")

    case_id = str(uuid.uuid4())
    source_digest = hashlib.sha256(f"{source_type}:{source_reference}".encode("utf-8")).hexdigest()
    expires_at = utcnow() + datetime.timedelta(hours=expires_in_hours)

    change_case = PayeeChangeCase(
        id=case_id,
        vendor_id=vendor_id,
        base_version_id=active_version.id,
        case_type=case_type,
        proposed_recipient=clean_proposed,
        source_type=source_type,
        source_digest=source_digest,
        requester_id=requester_id,
        state="HELD",
        rejection_reason=None,
        created_at=utcnow(),
        updated_at=utcnow(),
        expires_at=expires_at,
    )
    session.add(change_case)
    session.flush()

    record_audit_event(
        session=session,
        event_type="PAYEE_CHANGE_PROPOSED_HELD" if case_type == "RECIPIENT_CHANGE_PROPOSAL" else "MANUAL_EXTRACTION_REVIEW_HELD",
        actor_id=requester_id,
        entity_type="PAYEE_CHANGE_CASE",
        entity_id=case_id,
        state_before=None,
        state_after="HELD",
        details={
            "vendor_id": vendor_id,
            "case_type": case_type,
            "base_version_id": active_version.id,
            "current_recipient": active_version.paypal_recipient,
            "proposed_recipient": clean_proposed,
            "source_type": source_type,
        },
    )
    return change_case


def issue_verification_challenge(
    session: Session,
    case_id: str,
    actor_id: Optional[str] = None,
    expiry_seconds: int = CHALLENGE_DEFAULT_EXPIRY_SECONDS,
) -> Tuple[VerificationChallenge, str]:
    """
    Issues an out-of-band verification challenge bound to the case.
    The challenge token is dispatched ONLY to the previously established trusted contact.
    Stores ONLY keyed HMAC-SHA256, never plaintext or bare hashes.
    Returns (challenge_record, plaintext_token_for_dispatch).
    """
    case = session.query(PayeeChangeCase).filter_by(id=case_id).first()
    if not case:
        raise ValueError(f"PayeeChangeCase '{case_id}' not found.")

    if getattr(case, "case_type", None) == "MANUAL_EXTRACTION_REVIEW" or not case.proposed_recipient:
        raise SecurityViolationError(
            f"Cannot issue verification challenge for case '{case_id}': case is in MANUAL_EXTRACTION_REVIEW "
            "with no validated recipient. An explicit payee-change proposal must be created first."
        )

    from app.models import validate_paypal_recipient_email
    validate_paypal_recipient_email(case.proposed_recipient)

    if case.state not in ("HELD", "CHALLENGE_ISSUED"):
        raise InvalidStateTransitionError(f"Cannot issue challenge for case in state '{case.state}'.")

    vendor = get_vendor(session, case.vendor_id)
    check_vendor_active(vendor)

    challenge_id = str(uuid.uuid4())
    # Generate high-entropy unguessable token
    plaintext_token = secrets.token_urlsafe(24)

    # Keyed HMAC construction bound to challenge_id, case_id, and proposed_recipient
    token_hmac = compute_challenge_token_hmac(
        challenge_id=challenge_id,
        case_id=case.id,
        proposed_recipient=case.proposed_recipient,
        token=plaintext_token,
    )

    candidate_digest = compute_candidate_digest(
        case_id=case.id,
        vendor_id=case.vendor_id,
        base_version_id=case.base_version_id,
        proposed_recipient=case.proposed_recipient,
    )

    expires_at = utcnow() + datetime.timedelta(seconds=expiry_seconds)

    challenge = VerificationChallenge(
        id=challenge_id,
        case_id=case.id,
        vendor_id=case.vendor_id,
        bound_base_version_id=case.base_version_id,
        bound_proposed_recipient=case.proposed_recipient,
        bound_candidate_digest=candidate_digest,
        token_hash=token_hmac,
        delivery_channel="TRUSTED_EMAIL",
        delivery_destination=vendor.trusted_contact_email,  # Strictly pre-existing contact
        attempts=0,
        max_attempts=MAX_VERIFICATION_ATTEMPTS,
        expires_at=expires_at,
        used_at=None,
        rejected_at=None,
        created_at=utcnow(),
    )
    session.add(challenge)

    case.state = "CHALLENGE_ISSUED"
    case.updated_at = utcnow()
    session.flush()

    record_audit_event(
        session=session,
        event_type="CHALLENGE_ISSUED",
        actor_id=actor_id,
        entity_type="VERIFICATION_CHALLENGE",
        entity_id=challenge_id,
        state_before="HELD",
        state_after="CHALLENGE_ISSUED",
        details={
            "case_id": case.id,
            "destination": vendor.trusted_contact_email,
            "expires_at": expires_at.isoformat(),
            "hmac_binding": "challenge_id+case_id+proposed_recipient",
        },
    )

    return challenge, plaintext_token


def verify_vendor_confirmation(
    session: Session,
    case_id: str,
    submitted_token: str,
) -> PayeeChangeCase:
    """
    Vendor enters token to confirm they requested the recipient change.
    Requirements:
    - Verifies keyed HMAC-SHA256 with constant-time equality.
    - Single-use: marks used_at atomically.
    - Rate limits: rejects if max attempts exceeded.
    - Transitions case to VENDOR_CONFIRMED.
    - Does NOT activate the version! A separate approver is still required.
    """
    case = session.query(PayeeChangeCase).filter_by(id=case_id).first()
    if not case:
        raise ValueError(f"PayeeChangeCase '{case_id}' not found.")

    if getattr(case, "case_type", None) == "MANUAL_EXTRACTION_REVIEW" or not case.proposed_recipient:
        raise SecurityViolationError(
            f"Cannot verify confirmation for case '{case_id}': manual review cases cannot be confirmed as payee changes."
        )

    from app.models import validate_paypal_recipient_email
    validate_paypal_recipient_email(case.proposed_recipient)

    vendor = get_vendor(session, case.vendor_id)
    check_vendor_active(vendor)

    if case.state != "CHALLENGE_ISSUED":
        raise InvalidStateTransitionError(f"Case '{case_id}' is not in CHALLENGE_ISSUED state (current: {case.state}).")

    challenge = (
        session.query(VerificationChallenge)
        .filter_by(case_id=case_id)
        .order_by(VerificationChallenge.created_at.desc())
        .first()
    )
    if not challenge:
        raise ValueError(f"No challenge found for case '{case_id}'.")

    # Check expiration
    if to_naive_utc(utcnow()) > to_naive_utc(challenge.expires_at):
        case.state = "EXPIRED"
        case.updated_at = utcnow()
        session.flush()
        record_audit_event(
            session=session,
            event_type="CHALLENGE_EXPIRED",
            entity_type="VERIFICATION_CHALLENGE",
            entity_id=challenge.id,
            state_before="CHALLENGE_ISSUED",
            state_after="EXPIRED",
        )
        raise ExpiredChallengeError("Verification challenge has expired.")

    # Check if already consumed or rejected
    if challenge.used_at is not None:
        raise InvalidChallengeError("Challenge token has already been consumed (single-use).")

    if challenge.rejected_at is not None:
        raise InvalidChallengeError("Challenge has been rejected due to compromise suspicion.")

    # Check attempt limit
    if challenge.attempts >= challenge.max_attempts:
        raise MaxAttemptsExceededError("Maximum verification attempts exceeded.")

    challenge.attempts += 1

    # Verify constant-time keyed HMAC match
    submitted_hmac = compute_challenge_token_hmac(
        challenge_id=challenge.id,
        case_id=case.id,
        proposed_recipient=case.proposed_recipient,
        token=submitted_token,
    )
    if not hmac.compare_digest(submitted_hmac, challenge.token_hash):
        session.flush()
        if challenge.attempts >= challenge.max_attempts:
            raise MaxAttemptsExceededError("Maximum verification attempts exceeded. Challenge locked.")
        raise InvalidChallengeError("Invalid verification token.")

    # Verification successful: consume token atomically
    challenge.used_at = utcnow()
    case.state = "VENDOR_CONFIRMED"
    case.updated_at = utcnow()
    session.flush()

    record_audit_event(
        session=session,
        event_type="VENDOR_CONFIRMED_CHANGE",
        entity_type="PAYEE_CHANGE_CASE",
        entity_id=case.id,
        state_before="CHALLENGE_ISSUED",
        state_after="VENDOR_CONFIRMED",
        details={
            "challenge_id": challenge.id,
            "proposed_recipient": case.proposed_recipient,
        },
    )
    return case


def record_vendor_rejection_compromise(
    session: Session,
    case_id: str,
    actor_note: str = "Vendor clicked 'This wasn't me'",
) -> PayeeChangeCase:
    """
    Vendor flags the request as unauthorized ('This wasn't me').
    Explicit REJECTED_COMPROMISE_SUSPECTED state.
    Freezes the vendor master status permanently and revokes all challenges.
    """
    case = session.query(PayeeChangeCase).filter_by(id=case_id).first()
    if not case:
        raise ValueError(f"PayeeChangeCase '{case_id}' not found.")

    prev_state = case.state
    case.state = "REJECTED_COMPROMISE_SUSPECTED"
    case.rejection_reason = actor_note
    case.updated_at = utcnow()

    # Revoke all outstanding challenges for this case
    challenges = session.query(VerificationChallenge).filter_by(case_id=case_id).all()
    now = utcnow()
    for ch in challenges:
        if ch.rejected_at is None and ch.used_at is None:
            ch.rejected_at = now

    # Freeze the vendor
    freeze_vendor(
        session=session,
        vendor_id=case.vendor_id,
        actor_id=None,
        reason=f"Suspected compromise: {actor_note} on case {case_id}",
    )

    session.flush()

    record_audit_event(
        session=session,
        event_type="VENDOR_FLAGGED_COMPROMISE",
        entity_type="PAYEE_CHANGE_CASE",
        entity_id=case.id,
        state_before=prev_state,
        state_after="REJECTED_COMPROMISE_SUSPECTED",
        details={
            "reason": actor_note,
            "vendor_id": case.vendor_id,
        },
    )
    return case
