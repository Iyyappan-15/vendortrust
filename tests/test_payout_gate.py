"""
tests/test_payout_gate.py — Tests for Strict Payout Interface, Recipient Injection Refusal, and Idempotency
"""

import pytest
from app.models import PayoutAttempt
from app.services.approvals import approve_payment_intent, create_payment_intent
from app.services.exceptions import (
    DuplicatePayoutError,
    InvalidStateTransitionError,
    SecurityViolationError,
)
from app.services.payouts import MockPayoutProvider, submit_approved_payout


def test_payout_resolves_recipient_exclusively_from_vendor_version(db_session, seeded_env):
    """
    CRITICAL SECURITY INVARIANT:
    Payout execution resolves recipient email strictly from the verified immutable vendor version.
    It does not accept or trust any external email override.
    """
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]
    v1 = seeded_env["v1"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-PAY-001",
        amount_minor=100,  # $1.00 USD
        currency="USD",
        requester_id=asha.id,
    )
    approve_payment_intent(db_session, intent.id, approver_id=ravi.id)

    attempt = submit_approved_payout(
        session=db_session,
        payment_intent_id=intent.id,
        operator_actor_id="operator_01",
    )

    assert attempt.state == "SUCCESS"
    assert attempt.resolved_recipient == v1.paypal_recipient
    assert attempt.amount_minor == 100
    assert attempt.currency == "USD"
    assert intent.state == "SETTLED"


def test_duplicate_payout_instructions_refused(db_session, seeded_env):
    """Submitting a second payout on an already settled payment intent is strictly refused."""
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-PAY-DUP",
        amount_minor=250,
        currency="USD",
        requester_id=asha.id,
    )
    approve_payment_intent(db_session, intent.id, approver_id=ravi.id)

    # First payout execution succeeds
    submit_approved_payout(db_session, payment_intent_id=intent.id)

    # Second payout execution on the same intent must fail
    with pytest.raises(DuplicatePayoutError, match="already been successfully paid out"):
        submit_approved_payout(db_session, payment_intent_id=intent.id)


def test_uncertain_provider_outcome_transitions_to_reconcile_required(db_session, seeded_env):
    """
    If provider call times out or outcome is uncertain, the system transitions to
    RECONCILE_REQUIRED and preserves the stable sender_batch_id.
    It does NOT mark SUCCESS or create a new batch.
    """
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-PAY-TIMEOUT",
        amount_minor=500,
        currency="USD",
        requester_id=asha.id,
    )
    approve_payment_intent(db_session, intent.id, approver_id=ravi.id)

    timeout_provider = MockPayoutProvider(simulate_timeout=True)
    attempt = submit_approved_payout(
        session=db_session,
        payment_intent_id=intent.id,
        provider=timeout_provider,
    )

    assert attempt.state == "RECONCILE_REQUIRED"
    assert intent.state == "RECONCILE_REQUIRED"
    assert attempt.sender_batch_id is not None
    assert attempt.sender_item_id is not None


def test_unapproved_payment_intent_cannot_execute_payout(db_session, seeded_env):
    """A payment intent still awaiting approval cannot execute a payout."""
    asha = seeded_env["asha"]
    vendor = seeded_env["vendor"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-UNAPPROVED",
        amount_minor=300,
        currency="USD",
        requester_id=asha.id,
    )

    with pytest.raises(InvalidStateTransitionError, match="expected 'APPROVED'"):
        submit_approved_payout(db_session, payment_intent_id=intent.id)


def test_mismatched_approval_currency_fails(db_session, seeded_env):
    """If the intent's currency is modified after approval, payout execution fails."""
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-CURR-MISMATCH",
        amount_minor=1000,
        currency="USD",
        requester_id=asha.id,
    )
    approve_payment_intent(db_session, intent.id, approver_id=ravi.id)

    # Malicious modification: change currency to EUR
    intent.currency = "EUR"
    db_session.flush()

    with pytest.raises(SecurityViolationError, match="Mismatched payment intent amount/currency"):
        submit_approved_payout(db_session, payment_intent_id=intent.id)


def test_payout_fails_if_approval_is_expired(db_session, seeded_env):
    """An approved payment intent whose approval has lapsed cannot be submitted."""
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-EXPIRED-APPR",
        amount_minor=800,
        currency="USD",
        requester_id=asha.id,
    )
    # Approve with negative expiration
    approve_payment_intent(db_session, intent.id, approver_id=ravi.id, expires_in_seconds=-10)

    with pytest.raises(SecurityViolationError, match="Approval has expired"):
        submit_approved_payout(db_session, payment_intent_id=intent.id)


def test_recipient_injection_via_tampered_approval_bound_recipient_refused(db_session, seeded_env):
    """
    If an attacker modifies approval.bound_recipient to point to an attacker email,
    the payout engine compares it with the immutable VendorVersion and rejects with SecurityViolationError.
    """
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-INJECT",
        amount_minor=1000,
        currency="USD",
        requester_id=asha.id,
    )
    approval = approve_payment_intent(db_session, intent.id, approver_id=ravi.id)

    # Injected attacker email directly into approval table
    approval.bound_recipient = "attacker-injected@example.test"
    db_session.flush()

    with pytest.raises(SecurityViolationError):
        submit_approved_payout(db_session, payment_intent_id=intent.id)

