"""
app/services/challenges.py — Payee Change Cases & Out-of-Band Challenge Protocol
"""

import datetime
import hashlib
import hmac
import secrets
import uuid
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from app.models import PayeeChangeCase, VerificationChallenge, Vendor, VendorVersion, utcnow
from app.services.audit import record_audit_event
from app.services.exceptions import (
    ExpiredChallengeError,
    InvalidChallengeError,
    InvalidStateTransitionError,
    MaxAttemptsExceededError,
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


def hash_token(token: str) -> str:
    """Compute deterministic SHA-256 hash of a plaintext verification token."""
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


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
    proposed_recipient: str,
    source_type: str,
    source_reference: str,
    requester_id: str,
    expires_in_hours: int = 48,
) -> PayeeChangeCase:
    """
    Creates a new payee change case.
    A proposed recipient change enters the HELD state immediately.
    It can NEVER authorize or activate a change on its own.
    """
    vendor = get_vendor(session, vendor_id)
    check_vendor_active(vendor)

    active_version = session.query(VendorVersion).filter_by(id=vendor.active_version_id).first()
    if not active_version:
        raise ValueError(f"Vendor '{vendor_id}' has no active version.")

    clean_proposed = proposed_recipient.strip().lower()

    # If the requested recipient is identical to active version, no change case needed
    if clean_proposed == active_version.paypal_recipient.lower():
        raise ValueError("Proposed recipient matches existing active vendor recipient.")

    case_id = str(uuid.uuid4())
    source_digest = hashlib.sha256(f"{source_type}:{source_reference}".encode("utf-8")).hexdigest()
    expires_at = utcnow() + datetime.timedelta(hours=expires_in_hours)

    change_case = PayeeChangeCase(
        id=case_id,
        vendor_id=vendor_id,
        base_version_id=active_version.id,
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
        event_type="PAYEE_CHANGE_PROPOSED_HELD",
        actor_id=requester_id,
        entity_type="PAYEE_CHANGE_CASE",
        entity_id=case_id,
        state_before=None,
        state_after="HELD",
        details={
            "vendor_id": vendor_id,
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
    The database stores ONLY the token hash, never the plaintext token.
    Returns (challenge_record, plaintext_token_for_dispatch).
    """
    case = session.query(PayeeChangeCase).filter_by(id=case_id).first()
    if not case:
        raise ValueError(f"PayeeChangeCase '{case_id}' not found.")

    if case.state not in ("HELD", "CHALLENGE_ISSUED"):
        raise InvalidStateTransitionError(f"Cannot issue challenge for case in state '{case.state}'.")

    vendor = get_vendor(session, case.vendor_id)
    check_vendor_active(vendor)

    # Generate high-entropy unguessable token (e.g. 32-byte urlsafe string or 6-digit cryptographic OTP)
    plaintext_token = secrets.token_urlsafe(24)
    token_digest = hash_token(plaintext_token)

    candidate_digest = compute_candidate_digest(
        case_id=case.id,
        vendor_id=case.vendor_id,
        base_version_id=case.base_version_id,
        proposed_recipient=case.proposed_recipient,
    )

    challenge_id = str(uuid.uuid4())
    expires_at = utcnow() + datetime.timedelta(seconds=expiry_seconds)

    challenge = VerificationChallenge(
        id=challenge_id,
        case_id=case.id,
        vendor_id=case.vendor_id,
        bound_base_version_id=case.base_version_id,
        bound_proposed_recipient=case.proposed_recipient,
        bound_candidate_digest=candidate_digest,
        token_hash=token_digest,
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
    - Verifies token hash with constant-time equality.
    - Single-use: marks used_at.
    - Rate limits: rejects if max attempts exceeded.
    - Transitions case to VENDOR_CONFIRMED.
    - Does NOT activate the version! A separate approver is still required.
    """
    case = session.query(PayeeChangeCase).filter_by(id=case_id).first()
    if not case:
        raise ValueError(f"PayeeChangeCase '{case_id}' not found.")

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

    # Verify constant-time token hash match
    submitted_hash = hash_token(submitted_token)
    if not hmac.compare_digest(submitted_hash, challenge.token_hash):
        session.flush()
        if challenge.attempts >= challenge.max_attempts:
            raise MaxAttemptsExceededError("Maximum verification attempts exceeded. Challenge locked.")
        raise InvalidChallengeError("Invalid verification token.")

    # Verification successful: consume token
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
