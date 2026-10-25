"""
app/services/payouts.py — Strict Payout Submission Interface & Idempotency Controls
"""

import datetime
import uuid
from typing import Any, Dict, Optional, Protocol
from sqlalchemy.exc import IntegrityError
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

    def get_batch_status(self, payout_batch_id: str) -> Dict[str, Any]:
        ...

    def get_item_status(self, payout_item_id: str) -> Dict[str, Any]:
        ...


class MockPayoutProvider:
    """
    Simulated payout provider for testing and deterministic validation.
    No network requests made. Prominently records mock execution.
    """
    def __init__(self, desired_item_status: str = "SUCCESS", simulate_timeout: bool = False, on_dispatch=None):
        self.desired_item_status = desired_item_status
        self.simulate_timeout = simulate_timeout
        self.on_dispatch = on_dispatch  # Hook to inspect DB state during network transit

    def execute_payout(
        self,
        sender_batch_id: str,
        sender_item_id: str,
        recipient_email: str,
        amount_minor: int,
        currency: str,
    ) -> Dict[str, Any]:
        if self.on_dispatch:
            self.on_dispatch(sender_batch_id, sender_item_id)

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

    def get_batch_status(self, payout_batch_id: str) -> Dict[str, Any]:
        return {
            "batch_status": "SUCCESS" if self.desired_item_status == "SUCCESS" else "PROCESSING",
            "first_item_id": f"item_for_{payout_batch_id}",
            "first_item_status": self.desired_item_status,
        }

    def get_item_status(self, payout_item_id: str) -> Dict[str, Any]:
        return {
            "transaction_status": self.desired_item_status,
            "time_processed": utcnow().isoformat(),
        }


def to_naive_utc(dt: datetime.datetime) -> datetime.datetime:
    """Normalize datetime to naive UTC for consistent SQLite comparisons."""
    if dt.tzinfo is not None:
        return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt


def reconcile_payout_attempt(
    session: Session,
    payout_attempt_id: str,
    provider: PayoutProviderProtocol,
) -> PayoutAttempt:
    """
    Reconciles an in-flight, pending, or uncertain payout attempt against provider records.
    Never submits a new payout instruction; only checks the existing batch and item.
    """
    attempt = session.query(PayoutAttempt).filter_by(id=payout_attempt_id).first()
    if not attempt:
        raise ValueError(f"PayoutAttempt '{payout_attempt_id}' not found.")

    intent = session.query(PaymentIntent).filter_by(id=attempt.payment_intent_id).first()

    if attempt.payout_item_id and hasattr(provider, "get_item_status"):
        item_res = provider.get_item_status(attempt.payout_item_id)
        tx_status = item_res.get("transaction_status")
        if tx_status:
            attempt.last_provider_check = utcnow()
            if tx_status == "SUCCESS":
                attempt.state = "SUCCESS"
                if intent:
                    intent.state = "SETTLED"
            elif tx_status in ("PENDING", "PROCESSING", "UNCLAIMED"):
                attempt.state = "PENDING"
            elif tx_status in ("FAILED", "RETURNED", "BLOCKED"):
                attempt.state = "FAILED"
                if intent:
                    intent.state = "FAILED"
            session.commit()
            return attempt

    if attempt.payout_batch_id and hasattr(provider, "get_batch_status"):
        batch_res = provider.get_batch_status(attempt.payout_batch_id)
        b_item_status = batch_res.get("first_item_status")
        if b_item_status:
            attempt.last_provider_check = utcnow()
            if b_item_status == "SUCCESS":
                attempt.state = "SUCCESS"
                if intent:
                    intent.state = "SETTLED"
            elif b_item_status in ("PENDING", "PROCESSING"):
                attempt.state = "PENDING"
            session.commit()
            return attempt

    return attempt


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
    3. Amount, currency, and invoice reference are read strictly from the approved intent.
    4. Validates approval signature/digest, expiration, and invalidation status.
    5. Checks vendor status (must not be FROZEN).
    6. Ensures version is still the active version of the vendor.
    7. DURABLE PRE-COMMIT & CRASH RESILIENCE:
       - If an attempt was already committed in RESERVED state (e.g. recovery from crash),
         it reuses the EXACT SAME sender_batch_id and sender_item_id.
       - Never creates a duplicate attempt. Unique constraint on payment_intent_id enforces this.
       - Dispatches to provider and updates final item outcome.
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

    attempt: Optional[PayoutAttempt] = None

    if existing_attempt:
        if existing_attempt.state == "SUCCESS":
            raise DuplicatePayoutError(f"Payment intent '{intent.id}' has already been successfully paid out.")
        if existing_attempt.state in ("SUBMITTED", "PENDING", "PROCESSING", "RECONCILE_REQUIRED"):
            # Return existing attempt to enforce idempotency
            return existing_attempt
        if existing_attempt.state == "RESERVED" and not existing_attempt.payout_batch_id:
            # Crash recovery immediately after reservation commit:
            # Reuse the already-committed attempt and its stable sender_batch_id!
            attempt = existing_attempt

    if attempt is None and intent.state != "APPROVED":
        raise InvalidStateTransitionError(
            f"Cannot execute payout for intent '{payment_intent_id}': state is '{intent.state}', expected 'APPROVED'."
        )

    # Step 2: Load and validate approval
    if not intent.approval_id:
        raise SecurityViolationError("Payment intent lacks an associated approval.")

    approval = session.query(Approval).filter_by(id=intent.approval_id).first()
    if not approval or approval.decision != "APPROVED":
        raise SecurityViolationError("Approval record is missing or not APPROVED.")

    # Prevent cross-intent approval reuse
    if approval.payment_intent_id != intent.id:
        raise SecurityViolationError("Cross-intent approval reuse detected! Approval is not bound to this payment intent.")

    if approval.invalidated_at is not None:
        raise SecurityViolationError(
            f"Approval was invalidated on {approval.invalidated_at}: {approval.invalidation_reason}"
        )

    if to_naive_utc(utcnow()) > to_naive_utc(approval.expires_at):
        intent.state = "INVALIDATED"
        session.commit()
        raise SecurityViolationError("Approval has expired.")

    # Step 3: Verify Approval Digest Integrity (Cryptographically binds invoice reference too!)
    expected_digest = compute_approval_digest(
        approval_type=approval.approval_type,
        bound_vendor_version_id=approval.bound_vendor_version_id,
        bound_recipient=approval.bound_recipient,
        approver_id=approval.approver_id,
        requester_id=approval.requester_id,
        expires_at=approval.expires_at,
        bound_amount_minor=approval.bound_amount_minor,
        bound_currency=approval.bound_currency,
        bound_invoice_reference=approval.bound_invoice_reference,
        payment_intent_id=intent.id,
    )
    if approval.digest != expected_digest:
        raise SecurityViolationError("Approval digest verification failed! Parameters have been tampered with.")

    # Verify amount, currency, and invoice reference match approval
    if approval.bound_amount_minor != intent.amount_minor or approval.bound_currency != intent.currency:
        raise SecurityViolationError("Mismatched payment intent amount/currency against approval binding.")

    if approval.bound_invoice_reference != intent.invoice_reference:
        raise SecurityViolationError("Mismatched invoice reference against approval binding.")

    # Step 4: Verify Vendor and Version Integrity
    vendor = get_vendor(session, intent.vendor_id)
    check_vendor_active(vendor)

    if vendor.active_version_id != approval.bound_vendor_version_id:
        raise StaleVersionError(
            f"Active vendor version '{vendor.active_version_id}' does not match approved version '{approval.bound_vendor_version_id}'."
        )

    version = session.query(VendorVersion).filter_by(id=approval.bound_vendor_version_id).first()
    if not version or vendor.active_version_id != version.id:
        raise StaleVersionError(f"Vendor version '{approval.bound_vendor_version_id}' is superseded.")

    # Step 5: STRICT RECIPIENT RESOLUTION
    # Recipient is resolved strictly from the verified immutable vendor version record
    verified_recipient = version.paypal_recipient.strip().lower()
    if verified_recipient != approval.bound_recipient.lower():
        raise SecurityViolationError("Version recipient does not match approval binding.")

    # Step 6: Persist and COMMIT PayoutAttempt in RESERVED state BEFORE network submission (if not recovering)
    if attempt is None:
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
        try:
            session.add(attempt)
            intent.state = "SUBMISSION_RESERVED"

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
            # DURABLE COMMIT BEFORE NETWORK TRANSIT
            session.commit()
        except IntegrityError:
            # Handle concurrent race: another thread committed the reservation a microsecond earlier
            session.rollback()
            existing = session.query(PayoutAttempt).filter_by(payment_intent_id=intent.id).first()
            if existing:
                return existing
            raise

    # Step 7: Dispatch to Provider using the committed stable identifiers
    payout_provider = provider or MockPayoutProvider(desired_item_status="SUCCESS")
    try:
        provider_result = payout_provider.execute_payout(
            sender_batch_id=attempt.sender_batch_id,
            sender_item_id=attempt.sender_item_id,
            recipient_email=verified_recipient,
            amount_minor=intent.amount_minor,
            currency=intent.currency,
        )
    except Exception as e:
        # Safe handling of uncertain network exception: preserve stable IDs and mark RECONCILE_REQUIRED
        attempt.state = "RECONCILE_REQUIRED"
        intent.state = "RECONCILE_REQUIRED"
        attempt.provider_response_redacted = f"Provider network dispatch exception: {str(e)}"
        attempt.last_provider_check = utcnow()
        intent.updated_at = utcnow()
        session.commit()
        return attempt

    # Step 8: Reconcile provider result
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
    session.commit()

    return attempt
