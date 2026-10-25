import datetime
import time
import pytest
from app.web.session import (
    new_demo_session,
    get_simulated_challenge_otp,
    store_simulated_challenge_otp,
    consume_simulated_challenge_otp,
    _demo_store,
    _store_lock,
)
from app.services.ai_extract import (
    extract_candidate_payee_change,
    EXTRACTION_STATUS_UNCERTAIN,
    EXTRACTION_STATUS_NO_CHANGE,
    EXTRACTION_STATUS_CHANGE_DETECTED,
)
from app.services.intake import process_incoming_document
from app.services.vendor_registry import register_initial_vendor, seed_default_users
from app.models import utcnow


def test_ephemeral_otp_storage_and_consumption():
    session_token = new_demo_session()
    case_id = "test-case-uuid-12345"
    raw_token = "TEST-OTP-TOKEN-12345"
    # Challenge expires in the future (+900 seconds)
    exp = utcnow() + datetime.timedelta(seconds=900)

    # Store
    store_simulated_challenge_otp(session_token, case_id, raw_token, exp)
    
    # Retrieve
    retrieved = get_simulated_challenge_otp(session_token, case_id)
    assert retrieved == raw_token

    # Consume
    consume_simulated_challenge_otp(session_token, case_id)
    assert get_simulated_challenge_otp(session_token, case_id) is None


def test_ephemeral_otp_expiration():
    session_token = new_demo_session()
    case_id = "test-case-expired"
    raw_token = "EXPIRED-TOKEN"
    
    # Expired 100 seconds ago
    with _store_lock:
        _demo_store[session_token]["simulated_mailboxes"][case_id] = {
            "raw_token": raw_token,
            "expires_at": time.time() - 100,
            "consumed": False,
        }

    assert get_simulated_challenge_otp(session_token, case_id) is None


def test_extraction_uncertain_when_ai_fails_and_heuristic_ambiguous(monkeypatch):
    """When GEMINI returns error and heuristic has no clear match, classify EXTRACTION_UNCERTAIN."""
    from unittest.mock import MagicMock
    import httpx

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"

    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyDummyValidKeyWithSufficientLength12345")
    with monkeypatch.context() as m:
        m.setattr(httpx.Client, "post", lambda self, *args, **kwargs: mock_resp)
        result = extract_candidate_payee_change(
            "Here is the monthly statement for services rendered.",
            source_type="email_text",
            force_heuristic=False
        )
        assert result.extraction_status == EXTRACTION_STATUS_UNCERTAIN
        assert result.needs_human_review is True
        assert "500" in result.fallback_reason


def test_extraction_uncertain_intake_forces_hold(db_session, monkeypatch):
    """Intake pipeline with EXTRACTION_UNCERTAIN must create a HELD case, never clear."""
    from unittest.mock import MagicMock
    import httpx

    db = db_session
    asha, ravi = seed_default_users(db)
    vendor, v1 = register_initial_vendor(
        session=db,
        name="Acme Design Labs",
        trusted_contact_email="billing@acme.test",
        initial_paypal_recipient="active@acme.test",
        requester_id=asha.id,
        approver_id=ravi.id,
        independent_contact_proof_type="CONTRACT_ON_FILE",
        proof_reference="DOC-001",
    )
    db.commit()

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"

    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyDummyValidKeyWithSufficientLength12345")
    with monkeypatch.context() as m:
        m.setattr(httpx.Client, "post", lambda self, *args, **kwargs: mock_resp)
        res = process_incoming_document(
            session=db,
            vendor_id=vendor.id,
            untrusted_text="Invoice for monthly web hosting services.",
            source_type="invoice_text",
            source_reference="INV-9999",
            requester_id=asha.id,
            force_heuristic=False,
        )

    assert res.decision == "HOLD"
    assert res.reason_code == "EXTRACTION_UNCERTAIN_FORCED_HOLD"
    assert res.case is not None
    assert res.case.state == "HELD"
    assert res.case.case_type == "MANUAL_EXTRACTION_REVIEW"
    assert res.case.proposed_recipient is None


def test_manual_review_case_cannot_issue_challenge_or_activate_version(db_session):
    """
    Requirements:
    1. A manual extraction review case cannot issue a verification challenge.
    2. A manual extraction review case cannot be approved to create a new vendor version.
    3. An uncertainty placeholder or invalid email can NEVER become a trusted recipient.
    """
    from app.services.challenges import issue_verification_challenge, create_payee_change_case
    from app.services.approvals import approve_payee_change_case
    from app.services.exceptions import SecurityViolationError
    from app.models import VendorVersion, validate_paypal_recipient_email

    db = db_session
    asha, ravi = seed_default_users(db)
    vendor, v1 = register_initial_vendor(
        session=db,
        name="Security First LLC",
        trusted_contact_email="security@first.test",
        initial_paypal_recipient="legit@first.test",
        requester_id=asha.id,
        approver_id=ravi.id,
        independent_contact_proof_type="CONTRACT_ON_FILE",
        proof_reference="SEC-001",
    )
    db.commit()

    # Create a MANUAL_EXTRACTION_REVIEW case
    review_case = create_payee_change_case(
        session=db,
        vendor_id=vendor.id,
        proposed_recipient=None,
        source_type="invoice_text",
        source_reference="INV-UNCERTAIN",
        requester_id=asha.id,
        case_type="MANUAL_EXTRACTION_REVIEW",
    )
    db.commit()

    # 1. Challenge issuance must be refused
    with pytest.raises(SecurityViolationError, match="MANUAL_EXTRACTION_REVIEW"):
        issue_verification_challenge(
            session=db,
            case_id=review_case.id,
            actor_id=asha.id,
        )

    # 2. Even if someone forcefully changed state to VENDOR_CONFIRMED, approval must be refused
    review_case.state = "VENDOR_CONFIRMED"
    db.commit()

    with pytest.raises(SecurityViolationError, match="manual extraction review"):
        approve_payee_change_case(
            session=db,
            case_id=review_case.id,
            approver_id=ravi.id,
        )

    # 3. Validation helper rejects placeholders and malformed emails
    with pytest.raises(SecurityViolationError, match="Prohibited marker"):
        validate_paypal_recipient_email("EXTRACTION_UNCERTAIN_MANUAL_REVIEW_REQUIRED@domain.com")

    with pytest.raises(SecurityViolationError, match="Invalid PayPal recipient"):
        validate_paypal_recipient_email("not-an-email-address")

    # 4. Attempting to directly insert a VendorVersion with a placeholder or invalid email is blocked
    bad_version = VendorVersion(
        id="bad-v-999",
        vendor_id=vendor.id,
        version_number=2,
        paypal_recipient="EXTRACTION_UNCERTAIN_MANUAL_REVIEW_REQUIRED",
        contact_snapshot_email="test@test.com",
        created_by_user_id=asha.id,
        approved_by_user_id=ravi.id,
        content_digest="dummy",
    )
    db.add(bad_version)
    with pytest.raises(SecurityViolationError, match="Invalid PayPal recipient"):
        db.flush()
    db.rollback()
