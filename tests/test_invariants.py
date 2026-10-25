"""
tests/test_invariants.py — Tests for Separation of Duties and Authorization Invariants
"""

import pytest
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
from app.services.exceptions import SecurityViolationError
from app.services.vendor_registry import register_initial_vendor


def test_self_approval_blocked_on_vendor_onboarding(db_session, seeded_env):
    """A user cannot act as both requester and approver during vendor onboarding."""
    asha = seeded_env["asha"]

    with pytest.raises(SecurityViolationError, match="distinct individuals"):
        register_initial_vendor(
            session=db_session,
            name="Rogue Vendor",
            trusted_contact_email="rogue@example.test",
            initial_paypal_recipient="rogue@example.test",
            requester_id=asha.id,
            approver_id=asha.id,  # Self-approval attempt
            independent_contact_proof_type="CONTRACT_ON_FILE",
            proof_reference="DOC-999",
        )


def test_onboarding_requires_independent_proof_metadata(db_session, seeded_env):
    """First-time onboarding without independent contact proof is strictly refused."""
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]

    # Missing proof type
    with pytest.raises(SecurityViolationError, match="Invalid independent contact proof type"):
        register_initial_vendor(
            session=db_session,
            name="Unverified Vendor",
            trusted_contact_email="unverified@example.test",
            initial_paypal_recipient="unverified@example.test",
            requester_id=asha.id,
            approver_id=ravi.id,
            independent_contact_proof_type="",
            proof_reference="DOC-123",
        )

    # Missing proof reference
    with pytest.raises(SecurityViolationError, match="substantive independent proof reference"):
        register_initial_vendor(
            session=db_session,
            name="Unverified Vendor",
            trusted_contact_email="unverified@example.test",
            initial_paypal_recipient="unverified@example.test",
            requester_id=asha.id,
            approver_id=ravi.id,
            independent_contact_proof_type="CONTRACT_ON_FILE",
            proof_reference="",
        )


def test_self_approval_blocked_on_payee_change(db_session, seeded_env):
    """The requester of a payee change case cannot approve their own case."""
    asha = seeded_env["asha"]
    vendor = seeded_env["vendor"]

    case = create_payee_change_case(
        session=db_session,
        vendor_id=vendor.id,
        proposed_recipient="new-recipient@example.test",
        source_type="INVOICE_PROPOSAL",
        source_reference="INV-101",
        requester_id=asha.id,
    )

    _, token = issue_verification_challenge(db_session, case.id)
    verify_vendor_confirmation(db_session, case.id, token)

    # Asha (the requester) attempts to approve her own change case
    with pytest.raises(SecurityViolationError, match="Unauthorized self-approval"):
        approve_payee_change_case(
            session=db_session,
            case_id=case.id,
            approver_id=asha.id,  # Illegal self-approval
        )


def test_self_approval_blocked_on_payment_intent(db_session, seeded_env):
    """The creator/requester of a payment intent cannot approve that payment."""
    asha = seeded_env["asha"]
    vendor = seeded_env["vendor"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-102",
        amount_minor=5000,
        currency="USD",
        requester_id=asha.id,
    )

    # Asha attempts to approve her own payment intent
    with pytest.raises(SecurityViolationError, match="Unauthorized self-approval"):
        approve_payment_intent(
            session=db_session,
            payment_intent_id=intent.id,
            approver_id=asha.id,  # Illegal self-approval
        )


def test_non_approver_cannot_approve_payment_or_case(db_session, seeded_env):
    """A user who does not have the APPROVER role cannot approve transactions."""
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]

    # Ravi creates an intent
    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-103",
        amount_minor=2000,
        currency="USD",
        requester_id=ravi.id,
    )

    # Asha (REQUESTER role) attempts to approve it
    with pytest.raises(SecurityViolationError, match="does not possess the APPROVER role"):
        approve_payment_intent(
            session=db_session,
            payment_intent_id=intent.id,
            approver_id=asha.id,
        )
