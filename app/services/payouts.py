"""
app/services/payouts.py — Strict Payout Submission Interface & Idempotency Controls
"""

import datetime
import uuid
from typing import Any, Dict, Optional, Protocol
from sqlalchemy.orm import Session
from app.models import Approval, PaymentIntent, PayoutAttempt, Vendor, VendorVersion, utcnow
from app.services.approvals import compute_approval_digest
from app.services.audit import record_audit_event
from app.services.exceptions import (
    DuplicatePayoutError,
    InvalidStateTransitionError,
    SecurityViolationError,
    StaleVersionError,
    VendorFrozenError,
)
from app.services.vendor_registry import check_vendor_active, get_vendor


class PayoutProviderProtocol(Protocol):
    """Protocol for payout execution providers (e.g. Mock or PayPal Sandbox)."""
    def execute_payout(
        self,
        sender_batch_id: str,
        sender_item_id: str,
        recipient_email: str,
        amount_minor: int,
        currency: str,
    ) -> Dict[str, Any]:
        ...


class MockPayoutProvider:
    """
    Simulated payout provider for testing and deterministic validation.
    No network requests made. Prominently records mock execution.
    """
    def __init__(self, desired_item_status: str = "SUCCESS", simulate_timeout: bool = False):
        self.desired_item_status = desired_item_status
        self.simulate_timeout = simulate_timeout

    def execute_payout(
        self,
        sender_batch_id: str,
        sender_item_id: str,
        recipient_email: str,
        amount_minor: int,
        currency: str,
    ) -> Dict[str, Any]:
        if self.simulate_timeout:
            return {
                "success": False,
                "uncertain": True,
                "payout_batch_id": None,
                "payout_item_id": None,
                "batch_status": "TIMEOUT",
                "item_status": "RECONCILE_REQUIRED",
                "response_redacted": "Simulated connection timeout during provider dispatch.",
            }

        batch_id = f"mock_batch_{uuid.uuid4().hex[:10]}"
        item_id = f"mock_item_{uuid.uuid4().hex[:10]}"

        return {
            "success": self.desired_item_status == "SUCCESS",
            "uncertain": self.desired_item_status in ("PENDING", "PROCESSING", "RECONCILE_REQUIRED"),
            "payout_batch_id": batch_id,
            "payout_item_id": item_id,
            "batch_status": "SUCCESS" if self.desired_item_status == "SUCCESS" else "PROCESSING",
            "item_status": self.desired_item_status,
            "response_redacted": f"SIMULATED_MOCK_PROVIDER (recipient={recipient_email[:3]}***, amt={amount_minor})",
        }


def to_naive_utc(dt: datetime.datetime) -> datetime.datetime:
    """Normalize datetime to naive UTC for consistent SQLite comparisons."""
    if dt.tzinfo is not None:
        return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt


def submit_approved_payout(
    session: Session,
    payment_intent_id: str,
    operator_actor_id: Optional[str] = None,
    provider: Optional[PayoutProviderProtocol] = None,
) -> PayoutAttempt:
    """
    Strict payment execution interface.
    CRITICAL SECURITY INVARIANTS:
    1. Accepts ONLY payment_intent_id.
    2. Recipient email is NEVER accepted from caller or external input.
       It is resolved strictly from the immutable VendorVersion record!
    3. Amount and currency are read strictly from the approved intent.
    4. Validates approval signature/digest, expiration, and invalidation status.
    5. Checks vendor status (must not be FROZEN).
    6. Ensures version is still the active version of the vendor.
    7. Persists PayoutAttempt with unique batch/item IDs BEFORE provider dispatch (idempotency).
    """
    # Step 1: Load payment intent
    intent = session.query(PaymentIntent).filter_by(id=payment_intent_id).first()
    if not intent:
        raise ValueError(f"PaymentIntent '{payment_intent_id}' not found.")

    # Duplicate / Settled check first
    if intent.state == "SETTLED":
        raise DuplicatePayoutError(f"Payment intent '{intent.id}' has already been successfully paid out.")

    existing_attempt = (
        session.query(PayoutAttempt)
        .filter_by(payment_intent_id=intent.id)
        .first()
    )
    if existing_attempt and existing_attempt.state == "SUCCESS":
        raise DuplicatePayoutError(f"Payment intent '{intent.id}' has already been successfully paid out.")

    if intent.state != "APPROVED":
        raise InvalidStateTransitionError(
            f"Cannot execute payout for intent '{payment_intent_id}': state is '{intent.state}', expected 'APPROVED'."
        )

    # Step 2: Load approval
    if not intent.approval_id:
        raise SecurityViolationError("Payment intent lacks an associated approval.")

    approval = session.query(Approval).filter_by(id=intent.approval_id).first()
    if not approval or approval.decision != "APPROVED":
        raise SecurityViolationError("Approval record is missing or not APPROVED.")

    if approval.invalidated_at is not None:
        raise SecurityViolationError(
            f"Approval was invalidated on {approval.invalidated_at}: {approval.invalidation_reason}"
        )

    if to_naive_utc(utcnow()) > to_naive_utc(approval.expires_at):
        intent.state = "INVALIDATED"
        session.flush()
        raise SecurityViolationError("Approval has expired.")

    # Step 3: Verify Approval Digest Integrity
    expected_digest = compute_approval_digest(
        approval_type=approval.approval_type,
        bound_vendor_version_id=approval.bound_vendor_version_id,
        bound_recipient=approval.bound_recipient,
        approver_id=approval.approver_id,
        requester_id=approval.requester_id,
        expires_at=approval.expires_at,
        bound_amount_minor=approval.bound_amount_minor,
        bound_currency=approval.bound_currency,
        payment_intent_id=intent.id,
    )
    if approval.digest != expected_digest:
        raise SecurityViolationError("Approval digest verification failed! Parameters have been tampered with.")

    # Verify amount and currency match approval
    if approval.bound_amount_minor != intent.amount_minor or approval.bound_currency != intent.currency:
        raise SecurityViolationError("Mismatched payment intent amount/currency against approval binding.")

    # Step 4: Verify Vendor and Version Integrity
    vendor = get_vendor(session, intent.vendor_id)
    check_vendor_active(vendor)

    if vendor.active_version_id != approval.bound_vendor_version_id:
        raise StaleVersionError(
            f"Active vendor version '{vendor.active_version_id}' does not match approved version '{approval.bound_vendor_version_id}'."
        )

    version = session.query(VendorVersion).filter_by(id=approval.bound_vendor_version_id).first()
    if not version or version.superseded_at is not None:
        raise StaleVersionError(f"Vendor version '{approval.bound_vendor_version_id}' is superseded.")

    # Step 5: STRICT RECIPIENT RESOLUTION
    # Recipient is resolved strictly from the verified immutable vendor version record
    verified_recipient = version.paypal_recipient.strip().lower()
    if verified_recipient != approval.bound_recipient.lower():
        raise SecurityViolationError("Version recipient does not match approval binding.")

    # Step 6: Idempotency & Duplicate Prevention
    existing_attempt = (
        session.query(PayoutAttempt)
        .filter_by(payment_intent_id=intent.id)
        .first()
    )
    if existing_attempt:
        if existing_attempt.state == "SUCCESS":
            raise DuplicatePayoutError(f"Payment intent '{intent.id}' has already been successfully paid out.")
        if existing_attempt.state in ("RESERVED", "SUBMITTED"):
            # Return existing attempt to enforce idempotency
            return existing_attempt

    # Step 7: Persist PayoutAttempt in RESERVED state before network submission
    sender_batch_id = f"vt_batch_{uuid.uuid4().hex[:12]}"
    sender_item_id = f"vt_item_{uuid.uuid4().hex[:12]}"
    attempt_id = str(uuid.uuid4())

    attempt = PayoutAttempt(
        id=attempt_id,
        payment_intent_id=intent.id,
        sender_batch_id=sender_batch_id,
        sender_item_id=sender_item_id,
        payout_batch_id=None,
        payout_item_id=None,
        state="RESERVED",
        amount_minor=intent.amount_minor,
        currency=intent.currency,
        resolved_recipient=verified_recipient,
        created_at=utcnow(),
        last_provider_check=utcnow(),
        provider_response_redacted=None,
    )
    session.add(attempt)
    intent.state = "SUBMISSION_RESERVED"
    session.flush()

    record_audit_event(
        session=session,
        event_type="PAYOUT_RESERVED",
        actor_id=operator_actor_id,
        entity_type="PAYOUT_ATTEMPT",
        entity_id=attempt_id,
        state_before="APPROVED",
        state_after="RESERVED",
        details={
            "payment_intent_id": intent.id,
            "sender_batch_id": sender_batch_id,
            "sender_item_id": sender_item_id,
            "resolved_recipient": verified_recipient,
            "amount_minor": intent.amount_minor,
            "currency": intent.currency,
        },
    )

    # Step 8: Dispatch to Provider
    payout_provider = provider or MockPayoutProvider(desired_item_status="SUCCESS")
    provider_result = payout_provider.execute_payout(
        sender_batch_id=sender_batch_id,
        sender_item_id=sender_item_id,
        recipient_email=verified_recipient,
        amount_minor=intent.amount_minor,
        currency=intent.currency,
    )

    # Step 9: Reconcile provider result
    attempt.payout_batch_id = provider_result.get("payout_batch_id")
    attempt.payout_item_id = provider_result.get("payout_item_id")
    attempt.provider_response_redacted = provider_result.get("response_redacted")
    attempt.last_provider_check = utcnow()

    item_status = provider_result.get("item_status", "UNKNOWN")

    if item_status == "SUCCESS":
        attempt.state = "SUCCESS"
        intent.state = "SETTLED"
    elif item_status in ("PENDING", "PROCESSING", "UNCLAIMED"):
        attempt.state = "PENDING"
        intent.state = "SUBMITTED"
    elif provider_result.get("uncertain"):
        attempt.state = "RECONCILE_REQUIRED"
        intent.state = "RECONCILE_REQUIRED"
    else:
        attempt.state = "FAILED"
        intent.state = "FAILED"

    intent.updated_at = utcnow()
    session.flush()

    record_audit_event(
        session=session,
        event_type="PAYOUT_COMPLETED",
        actor_id=operator_actor_id,
        entity_type="PAYOUT_ATTEMPT",
        entity_id=attempt.id,
        state_before="RESERVED",
        state_after=attempt.state,
        details={
            "provider_batch_id": attempt.payout_batch_id,
            "provider_item_id": attempt.payout_item_id,
            "item_status": item_status,
            "resolved_recipient": verified_recipient,
        },
    )

    return attempt
