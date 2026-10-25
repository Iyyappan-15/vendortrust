"""
tests/test_approvals.py — Tests for Approval Binding, Tampering Refusal, and Stale Invalidation
"""

import datetime
import pytest
from app.models import Approval, PaymentIntent, utcnow
from app.services.approvals import (
    approve_payee_change_case,
    approve_payment_intent,
    create_payment_intent,
)
from app.services.challenges import (
    create_payee_change_case,
    issue_verification_challenge,
    verify_vendor_confirmation,
)
from app.services.exceptions import (
    InvalidStateTransitionError,
    SecurityViolationError,
    StaleVersionError,
)
from app.services.payouts import submit_approved_payout


def test_approval_cryptographic_parameter_binding(db_session, seeded_env):
    """Approval binds exact vendor version, recipient, amount, currency, invoice reference, and digest."""
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]
    v1 = seeded_env["v1"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-SEC-01",
        amount_minor=10000,
        currency="USD",
        requester_id=asha.id,
    )

    approval = approve_payment_intent(
        session=db_session,
        payment_intent_id=intent.id,
        approver_id=ravi.id,
    )

    assert approval.decision == "APPROVED"
    assert approval.bound_vendor_version_id == v1.id
    assert approval.bound_recipient == v1.paypal_recipient
    assert approval.bound_amount_minor == 10000
    assert approval.bound_currency == "USD"
    assert approval.bound_invoice_reference == "INV-SEC-01"
    assert approval.requester_id == asha.id
    assert approval.approver_id == ravi.id
    assert len(approval.digest) == 64


def test_unconfirmed_change_case_cannot_be_approved(db_session, seeded_env):
    """An approver cannot approve a payee change case that has not been confirmed by the vendor."""
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]

    case = create_payee_change_case(
        session=db_session,
        vendor_id=vendor.id,
        proposed_recipient="unconfirmed@example.test",
        source_type="INVOICE_PROPOSAL",
        source_reference="INV-UNCONFIRMED",
        requester_id=asha.id,
    )
    # Case is still HELD, no token confirmed

    with pytest.raises(InvalidStateTransitionError, match="VENDOR_CONFIRMED"):
        approve_payee_change_case(db_session, case.id, approver_id=ravi.id)


def test_stale_approval_invalidated_after_version_change(db_session, seeded_env):
    """
    CRITICAL INVARIANT 11:
    When a new vendor version N+1 is activated, any pre-existing pending payment approvals
    referencing the superseded version N are automatically invalidated.
    """
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]

    # 1. Create and approve a payment intent bound to Version 1
    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-BEFORE-CHANGE",
        amount_minor=1500,
        currency="USD",
        requester_id=asha.id,
    )
    approval = approve_payment_intent(
        session=db_session,
        payment_intent_id=intent.id,
        approver_id=ravi.id,
    )
    assert intent.state == "APPROVED"
    assert approval.invalidated_at is None

    # 2. A recipient change occurs: Vendor confirms, Approver Ravi approves version 2
    case = create_payee_change_case(
        session=db_session,
        vendor_id=vendor.id,
        proposed_recipient="vendor-v2@example.test",
        source_type="INVOICE_PROPOSAL",
        source_reference="INV-CHANGE",
        requester_id=asha.id,
    )
    _, token = issue_verification_challenge(db_session, case.id)
    verify_vendor_confirmation(db_session, case.id, token)

    approve_payee_change_case(db_session, case.id, approver_id=ravi.id)

    # 3. Check that the prior payment intent and approval are now INVALIDATED!
    db_session.refresh(intent)
    db_session.refresh(approval)

    assert intent.state == "INVALIDATED"
    assert approval.invalidated_at is not None
    assert "Superseded by vendor version 2" in approval.invalidation_reason

    # 4. Attempting to submit a payout on this invalidated intent MUST be refused!
    with pytest.raises(InvalidStateTransitionError, match="APPROVED"):
        submit_approved_payout(db_session, payment_intent_id=intent.id)


def test_tampered_approval_digest_refused(db_session, seeded_env):
    """If database values are altered behind the scenes, digest check fails."""
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-TAMPER",
        amount_minor=5000,
        currency="USD",
        requester_id=asha.id,
    )
    approval = approve_payment_intent(
        session=db_session,
        payment_intent_id=intent.id,
        approver_id=ravi.id,
    )

    # Malicious actor tampers with the intent amount without recomputing approval digest
    intent.amount_minor = 999999  # $9,999.99
    db_session.flush()

    with pytest.raises(SecurityViolationError, match="digest verification failed|Mismatched payment intent"):
        submit_approved_payout(db_session, payment_intent_id=intent.id)


def test_cross_intent_approval_reuse_refused(db_session, seeded_env):
    """
    An approval granted for Intent A cannot be attached to Intent B,
    even if amount, currency, and vendor are identical.
    """
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]

    intent_a = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-A",
        amount_minor=2000,
        currency="USD",
        requester_id=asha.id,
    )
    approval_a = approve_payment_intent(
        session=db_session,
        payment_intent_id=intent_a.id,
        approver_id=ravi.id,
    )

    # Attacker creates Intent B for same amount and tries to reuse approval_a
    intent_b = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-B",
        amount_minor=2000,
        currency="USD",
        requester_id=asha.id,
    )
    intent_b.state = "APPROVED"
    intent_b.approval_id = approval_a.id  # Reusing approval from Intent A
    db_session.flush()

    with pytest.raises(SecurityViolationError, match="Cross-intent approval reuse detected"):
        submit_approved_payout(db_session, payment_intent_id=intent_b.id)


def test_approval_digest_detects_invoice_reference_tampering(db_session, seeded_env):
    """Modifying the invoice reference on an intent after approval breaks digest verification."""
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-LEGIT-100",
        amount_minor=4000,
        currency="USD",
        requester_id=asha.id,
    )
    approve_payment_intent(
        session=db_session,
        payment_intent_id=intent.id,
        approver_id=ravi.id,
    )

    # Attacker tampers with invoice reference
    intent.invoice_reference = "INV-FRAUD-999"
    db_session.flush()

    with pytest.raises(SecurityViolationError, match="digest verification failed|Mismatched invoice reference"):
        submit_approved_payout(db_session, payment_intent_id=intent.id)
