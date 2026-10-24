"""
app/services/approvals.py — Two-Person Separation, Invalidation Invariants, and Bound Approvals
"""

import datetime
import hashlib
import uuid
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from app.models import (
    Approval,
    PayeeChangeCase,
    PaymentIntent,
    User,
    Vendor,
    VendorVersion,
    utcnow,
)
from app.services.audit import record_audit_event
from app.services.exceptions import (
    InvalidStateTransitionError,
    SecurityViolationError,
    StaleVersionError,
    VendorFrozenError,
)
from app.services.vendor_registry import (
    check_vendor_active,
    compute_vendor_version_digest,
    get_vendor,
)

APPROVAL_DEFAULT_EXPIRY_SECONDS = 86400  # 24 hours


def compute_approval_digest(
    approval_type: str,
    bound_vendor_version_id: str,
    bound_recipient: str,
    approver_id: str,
    requester_id: str,
    expires_at: datetime.datetime,
    bound_amount_minor: Optional[int] = None,
    bound_currency: Optional[str] = None,
    case_id: Optional[str] = None,
    payment_intent_id: Optional[str] = None,
) -> str:
    """Compute cryptographic SHA-256 digest binding all critical approval parameters."""
    raw = (
        f"{approval_type}:"
        f"{case_id or 'NONE'}:"
        f"{payment_intent_id or 'NONE'}:"
        f"{bound_vendor_version_id}:"
        f"{bound_recipient.strip().lower()}:"
        f"{bound_amount_minor if bound_amount_minor is not None else 'NONE'}:"
        f"{bound_currency or 'NONE'}:"
        f"{requester_id}:"
        f"{approver_id}:"
        f"{expires_at.isoformat()}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def approve_payee_change_case(
    session: Session,
    case_id: str,
    approver_id: str,
    expires_in_seconds: int = APPROVAL_DEFAULT_EXPIRY_SECONDS,
) -> Tuple[PayeeChangeCase, VendorVersion]:
    """
    Independent internal approver accepts a vendor-confirmed recipient change.
    Requirements:
    1. Separation of duties: requester CANNOT approve own change.
    2. Approver must have role 'APPROVER'.
    3. Case must be in 'VENDOR_CONFIRMED' state.
    4. Atomically creates version N+1.
    5. Supersedes version N.
    6. Invalidates all pending payment intents and approvals bound to superseded version N.
    7. Transitions case to 'VERSION_ACTIVATED'.
    """
    case = session.query(PayeeChangeCase).filter_by(id=case_id).first()
    if not case:
        raise ValueError(f"PayeeChangeCase '{case_id}' not found.")

    if case.state != "VENDOR_CONFIRMED":
        raise InvalidStateTransitionError(
            f"Case '{case_id}' cannot be approved: current state is '{case.state}', expected 'VENDOR_CONFIRMED'."
        )

    # Invariant: Requester cannot approve own change!
    if case.requester_id == approver_id:
        raise SecurityViolationError(
            f"Unauthorized self-approval: Requester '{approver_id}' cannot approve their own change case."
        )

    # Validate approver has APPROVER role
    approver = session.query(User).filter_by(id=approver_id).first()
    if not approver or approver.role != "APPROVER":
        raise SecurityViolationError(f"User '{approver_id}' does not possess the APPROVER role.")

    vendor = get_vendor(session, case.vendor_id)
    check_vendor_active(vendor)

    base_version = session.query(VendorVersion).filter_by(id=case.base_version_id).first()
    if not base_version:
        raise ValueError(f"Base vendor version '{case.base_version_id}' not found.")

    # Create new immutable VendorVersion N+1
    new_version_number = base_version.version_number + 1
    new_version_id = str(uuid.uuid4())
    new_digest = compute_vendor_version_digest(
        vendor_id=vendor.id,
        version_number=new_version_number,
        paypal_recipient=case.proposed_recipient,
        contact_snapshot_email=vendor.trusted_contact_email,
    )

    new_version = VendorVersion(
        id=new_version_id,
        vendor_id=vendor.id,
        version_number=new_version_number,
        paypal_recipient=case.proposed_recipient.strip().lower(),
        contact_snapshot_email=vendor.trusted_contact_email.strip().lower(),
        verification_case_id=case.id,
        created_by_user_id=case.requester_id,
        approved_by_user_id=approver_id,
        created_at=utcnow(),
        superseded_at=None,
        content_digest=new_digest,
    )
    session.add(new_version)
    session.flush()  # Insert new version before updating foreign key pointer!

    # Supersede version N
    base_version.superseded_at = utcnow()

    # Update Vendor active version pointer
    vendor.active_version_id = new_version_id
    session.flush()

    # Create Approval record
    approval_id = str(uuid.uuid4())
    expires_at = utcnow() + datetime.timedelta(seconds=expires_in_seconds)
    appr_digest = compute_approval_digest(
        approval_type="CHANGE_CASE",
        bound_vendor_version_id=new_version_id,
        bound_recipient=case.proposed_recipient,
        approver_id=approver_id,
        requester_id=case.requester_id,
        expires_at=expires_at,
        case_id=case.id,
    )

    approval = Approval(
        id=approval_id,
        approval_type="CHANGE_CASE",
        case_id=case.id,
        payment_intent_id=None,
        requester_id=case.requester_id,
        approver_id=approver_id,
        decision="APPROVED",
        bound_vendor_version_id=new_version_id,
        bound_recipient=case.proposed_recipient.strip().lower(),
        bound_amount_minor=None,
        bound_currency=None,
        digest=appr_digest,
        expires_at=expires_at,
        created_at=utcnow(),
        invalidated_at=None,
        invalidation_reason=None,
    )
    session.add(approval)

    # Update case state
    case.state = "VERSION_ACTIVATED"
    case.updated_at = utcnow()

    # CRITICAL INVARIANT: Invalidate pending approvals and payment intents bound to base_version!
    stale_intents = (
        session.query(PaymentIntent)
        .filter(
            PaymentIntent.vendor_version_id == base_version.id,
            PaymentIntent.state.in_(["AWAITING_APPROVAL", "APPROVED"]),
        )
        .all()
    )

    for stale_intent in stale_intents:
        prev_intent_state = stale_intent.state
        stale_intent.state = "INVALIDATED"
        stale_intent.updated_at = utcnow()

        if stale_intent.approval_id:
            stale_approval = session.query(Approval).filter_by(id=stale_intent.approval_id).first()
            if stale_approval and not stale_approval.invalidated_at:
                stale_approval.invalidated_at = utcnow()
                stale_approval.invalidation_reason = (
                    f"Superseded by vendor version {new_version_number}"
                )

        record_audit_event(
            session=session,
            event_type="PAYMENT_INTENT_STALE_INVALIDATED",
            actor_id=approver_id,
            entity_type="PAYMENT_INTENT",
            entity_id=stale_intent.id,
            state_before=prev_intent_state,
            state_after="INVALIDATED",
            details={
                "reason": f"Superseded by vendor version {new_version_number}",
                "superseded_version_id": base_version.id,
                "new_version_id": new_version_id,
            },
        )

    session.flush()

    record_audit_event(
        session=session,
        event_type="VENDOR_VERSION_ACTIVATED",
        actor_id=approver_id,
        entity_type="VENDOR_VERSION",
        entity_id=new_version_id,
        state_before=f"v{base_version.version_number}",
        state_after=f"v{new_version_number}",
        details={
            "vendor_id": vendor.id,
            "new_recipient": case.proposed_recipient,
            "case_id": case.id,
            "invalidated_stale_intents_count": len(stale_intents),
        },
    )

    return case, new_version


def create_payment_intent(
    session: Session,
    vendor_id: str,
    invoice_reference: str,
    amount_minor: int,
    currency: str,
    requester_id: str,
) -> PaymentIntent:
    """
    Requester creates a payment intent bound to the vendor's currently active version.
    """
    if amount_minor <= 0:
        raise ValueError("Amount must be a positive integer in minor units.")

    vendor = get_vendor(session, vendor_id)
    check_vendor_active(vendor)

    active_version = session.query(VendorVersion).filter_by(id=vendor.active_version_id).first()
    if not active_version:
        raise ValueError(f"Vendor '{vendor_id}' has no active version.")

    intent_id = str(uuid.uuid4())
    intent = PaymentIntent(
        id=intent_id,
        vendor_id=vendor_id,
        vendor_version_id=active_version.id,
        invoice_reference=invoice_reference.strip(),
        amount_minor=amount_minor,
        currency=currency.strip().upper(),
        requester_id=requester_id,
        state="AWAITING_APPROVAL",
        approval_id=None,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    session.add(intent)
    session.flush()

    record_audit_event(
        session=session,
        event_type="PAYMENT_INTENT_CREATED",
        actor_id=requester_id,
        entity_type="PAYMENT_INTENT",
        entity_id=intent_id,
        state_before=None,
        state_after="AWAITING_APPROVAL",
        details={
            "vendor_id": vendor_id,
            "vendor_version_id": active_version.id,
            "amount_minor": amount_minor,
            "currency": currency,
            "recipient_snapshot": active_version.paypal_recipient,
        },
    )
    return intent


def approve_payment_intent(
    session: Session,
    payment_intent_id: str,
    approver_id: str,
    expires_in_seconds: int = APPROVAL_DEFAULT_EXPIRY_SECONDS,
) -> Approval:
    """
    Approver authorizes a payment intent.
    Requirements:
    1. Requester cannot approve own payment intent (requester_id != approver_id).
    2. Approver must hold APPROVER role.
    3. Vendor must be active (not frozen).
    4. Referenced vendor version must still be the current active version.
    5. Approval cryptographically binds intent, vendor version, recipient, amount, currency, and expiry.
    """
    intent = session.query(PaymentIntent).filter_by(id=payment_intent_id).first()
    if not intent:
        raise ValueError(f"PaymentIntent '{payment_intent_id}' not found.")

    if intent.state != "AWAITING_APPROVAL":
        raise InvalidStateTransitionError(
            f"Cannot approve PaymentIntent '{payment_intent_id}': state is '{intent.state}', expected 'AWAITING_APPROVAL'."
        )

    # Invariant: Requester cannot approve own payment!
    if intent.requester_id == approver_id:
        raise SecurityViolationError(
            f"Unauthorized self-approval: Requester '{approver_id}' cannot approve own payment intent."
        )

    # Check approver role
    approver = session.query(User).filter_by(id=approver_id).first()
    if not approver or approver.role != "APPROVER":
        raise SecurityViolationError(f"User '{approver_id}' does not possess the APPROVER role.")

    vendor = get_vendor(session, intent.vendor_id)
    check_vendor_active(vendor)

    # Ensure version is still active and not superseded
    if intent.vendor_version_id != vendor.active_version_id:
        raise StaleVersionError(
            f"Cannot approve: Vendor version '{intent.vendor_version_id}' is no longer active (current: '{vendor.active_version_id}')."
        )

    version = session.query(VendorVersion).filter_by(id=intent.vendor_version_id).first()
    if not version or version.superseded_at is not None:
        raise StaleVersionError(f"Cannot approve: Vendor version '{intent.vendor_version_id}' has been superseded.")

    approval_id = str(uuid.uuid4())
    expires_at = utcnow() + datetime.timedelta(seconds=expires_in_seconds)

    digest = compute_approval_digest(
        approval_type="PAYMENT_INTENT",
        bound_vendor_version_id=version.id,
        bound_recipient=version.paypal_recipient,
        approver_id=approver_id,
        requester_id=intent.requester_id,
        expires_at=expires_at,
        bound_amount_minor=intent.amount_minor,
        bound_currency=intent.currency,
        payment_intent_id=intent.id,
    )

    approval = Approval(
        id=approval_id,
        approval_type="PAYMENT_INTENT",
        case_id=None,
        payment_intent_id=intent.id,
        requester_id=intent.requester_id,
        approver_id=approver_id,
        decision="APPROVED",
        bound_vendor_version_id=version.id,
        bound_recipient=version.paypal_recipient.strip().lower(),
        bound_amount_minor=intent.amount_minor,
        bound_currency=intent.currency.strip().upper(),
        digest=digest,
        expires_at=expires_at,
        created_at=utcnow(),
        invalidated_at=None,
        invalidation_reason=None,
    )
    session.add(approval)

    intent.state = "APPROVED"
    intent.approval_id = approval_id
    intent.updated_at = utcnow()
    session.flush()

    record_audit_event(
        session=session,
        event_type="PAYMENT_INTENT_APPROVED",
        actor_id=approver_id,
        entity_type="PAYMENT_INTENT",
        entity_id=intent.id,
        state_before="AWAITING_APPROVAL",
        state_after="APPROVED",
        details={
            "approval_id": approval_id,
            "bound_version_id": version.id,
            "bound_recipient": version.paypal_recipient,
            "amount_minor": intent.amount_minor,
            "currency": intent.currency,
        },
    )
    return approval
