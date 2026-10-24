"""
tests/test_challenges.py — Tests for Verification Challenges, Rate Limiting, and Compromise Freeze
"""

import datetime
import pytest
from app.models import PayeeChangeCase, VerificationChallenge, utcnow
from app.services.challenges import (
    create_payee_change_case,
    hash_token,
    issue_verification_challenge,
    record_vendor_rejection_compromise,
    verify_vendor_confirmation,
)
from app.services.exceptions import (
    ExpiredChallengeError,
    InvalidChallengeError,
    MaxAttemptsExceededError,
    VendorFrozenError,
)


def test_challenge_stores_only_token_hash_not_plaintext(db_session, seeded_env):
    """The database must never contain the plaintext verification token."""
    asha = seeded_env["asha"]
    vendor = seeded_env["vendor"]

    case = create_payee_change_case(
        session=db_session,
        vendor_id=vendor.id,
        proposed_recipient="updated-acme@example.test",
        source_type="INVOICE_PROPOSAL",
        source_reference="INV-999",
        requester_id=asha.id,
    )

    challenge, plaintext_token = issue_verification_challenge(db_session, case.id)

    # Verify database record
    db_record = db_session.query(VerificationChallenge).filter_by(id=challenge.id).first()
    assert db_record.token_hash == hash_token(plaintext_token)
    assert plaintext_token not in db_record.token_hash
    # Destination must be strictly the pre-existing trusted contact
    assert db_record.delivery_destination == vendor.trusted_contact_email


def test_challenge_single_use_enforcement(db_session, seeded_env):
    """A verification token cannot be reused after successful confirmation."""
    asha = seeded_env["asha"]
    vendor = seeded_env["vendor"]

    case = create_payee_change_case(
        session=db_session,
        vendor_id=vendor.id,
        proposed_recipient="updated-acme@example.test",
        source_type="INVOICE_PROPOSAL",
        source_reference="INV-999",
        requester_id=asha.id,
    )

    _, plaintext_token = issue_verification_challenge(db_session, case.id)

    # First use succeeds
    updated_case = verify_vendor_confirmation(db_session, case.id, plaintext_token)
    assert updated_case.state == "VENDOR_CONFIRMED"

    # Second use fails
    with pytest.raises(Exception):  # Either invalid state transition or already consumed
        verify_vendor_confirmation(db_session, case.id, plaintext_token)


def test_challenge_expiration_enforcement(db_session, seeded_env):
    """Expired verification challenges are strictly rejected."""
    asha = seeded_env["asha"]
    vendor = seeded_env["vendor"]

    case = create_payee_change_case(
        session=db_session,
        vendor_id=vendor.id,
        proposed_recipient="updated-acme@example.test",
        source_type="INVOICE_PROPOSAL",
        source_reference="INV-999",
        requester_id=asha.id,
    )

    # Issue challenge with negative expiry (already expired)
    challenge, plaintext_token = issue_verification_challenge(db_session, case.id, expiry_seconds=-10)

    with pytest.raises(ExpiredChallengeError, match="expired"):
        verify_vendor_confirmation(db_session, case.id, plaintext_token)

    db_session.refresh(case)
    assert case.state == "EXPIRED"


def test_challenge_rate_limiting_max_attempts(db_session, seeded_env):
    """Three incorrect token attempts lock the challenge and raise MaxAttemptsExceededError."""
    asha = seeded_env["asha"]
    vendor = seeded_env["vendor"]

    case = create_payee_change_case(
        session=db_session,
        vendor_id=vendor.id,
        proposed_recipient="updated-acme@example.test",
        source_type="INVOICE_PROPOSAL",
        source_reference="INV-999",
        requester_id=asha.id,
    )

    challenge, correct_token = issue_verification_challenge(db_session, case.id)

    # Attempt 1: wrong token
    with pytest.raises(InvalidChallengeError):
        verify_vendor_confirmation(db_session, case.id, "wrong_token_1")

    # Attempt 2: wrong token
    with pytest.raises(InvalidChallengeError):
        verify_vendor_confirmation(db_session, case.id, "wrong_token_2")

    # Attempt 3: wrong token -> locks challenge
    with pytest.raises(MaxAttemptsExceededError):
        verify_vendor_confirmation(db_session, case.id, "wrong_token_3")

    # Even with the correct token now, it remains locked
    with pytest.raises(MaxAttemptsExceededError):
        verify_vendor_confirmation(db_session, case.id, correct_token)


def test_challenge_substitution_across_cases_rejected(db_session, seeded_env):
    """A valid token for Case 1 cannot confirm Case 2 (candidate/case binding)."""
    asha = seeded_env["asha"]
    vendor = seeded_env["vendor"]

    case1 = create_payee_change_case(
        session=db_session,
        vendor_id=vendor.id,
        proposed_recipient="hacker-one@example.test",
        source_type="INVOICE_PROPOSAL",
        source_reference="INV-001",
        requester_id=asha.id,
    )
    _, token1 = issue_verification_challenge(db_session, case1.id)

    case2 = create_payee_change_case(
        session=db_session,
        vendor_id=vendor.id,
        proposed_recipient="hacker-two@example.test",
        source_type="INVOICE_PROPOSAL",
        source_reference="INV-002",
        requester_id=asha.id,
    )
    _, token2 = issue_verification_challenge(db_session, case2.id)

    # Attempt to confirm Case 2 using Case 1's token
    with pytest.raises(InvalidChallengeError):
        verify_vendor_confirmation(db_session, case2.id, token1)


def test_vendor_rejection_compromise_freezes_vendor_permanently(db_session, seeded_env):
    """
    When vendor clicks 'This wasn't me':
    - Case transitions to REJECTED_COMPROMISE_SUSPECTED.
    - Outstanding challenges are revoked.
    - Vendor status transitions to FROZEN_SUSPECTED_COMPROMISE.
    - Future operations on the vendor are blocked.
    """
    asha = seeded_env["asha"]
    vendor = seeded_env["vendor"]

    case = create_payee_change_case(
        session=db_session,
        vendor_id=vendor.id,
        proposed_recipient="attacker@example.test",
        source_type="INVOICE_PROPOSAL",
        source_reference="INV-ATTACK",
        requester_id=asha.id,
    )
    challenge, token = issue_verification_challenge(db_session, case.id)

    # Vendor clicks "This wasn't me"
    frozen_case = record_vendor_rejection_compromise(db_session, case.id, "Unauthorized change attempt flagged")

    assert frozen_case.state == "REJECTED_COMPROMISE_SUSPECTED"
    db_session.refresh(vendor)
    assert vendor.status == "FROZEN_SUSPECTED_COMPROMISE"

    db_session.refresh(challenge)
    assert challenge.rejected_at is not None

    # Verifying the token now fails
    with pytest.raises(VendorFrozenError):
        verify_vendor_confirmation(db_session, case.id, token)

    # Any new change case on this vendor is blocked
    with pytest.raises(VendorFrozenError):
        create_payee_change_case(
            session=db_session,
            vendor_id=vendor.id,
            proposed_recipient="another@example.test",
            source_type="INVOICE_PROPOSAL",
            source_reference="INV-NEW",
            requester_id=asha.id,
        )
