"""
tests/test_gate2_idempotency.py — Regression tests for Gate 2 rerun idempotency, recovery & safety gates.

Ensures that:
1. Normal reruns of Gate 2 reconcile without submitting duplicate payouts.
2. Interrupted or non-terminal runs resume reconciliation using existing batch/item IDs.
3. Uncertain provider responses update attempt state without resubmitting payouts.
4. '--force-new-test' fails closed unless '--confirm-operator' is provided.
5. Authorized new tests generate unique test run identities and sender batch IDs.

ALL tests execute entirely in-memory with fake/mock providers to guarantee NO real PayPal sandbox funds are touched.
"""

import datetime
import json
import os
import uuid
import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, create_immutability_triggers
from app.models import (
    Approval,
    PayeeChangeCase,
    PaymentIntent,
    PayoutAttempt,
    User,
    Vendor,
    VendorVersion,
    utcnow,
)
from app.services.vendor_registry import register_initial_vendor, seed_default_users
from scripts.test_paypal_gate2 import (
    load_gate2_state,
    save_gate2_state,
    run_gate2,
)


class MockSandboxAdapter:
    """Mock adapter simulating PayPal sandbox responses without outbound network calls."""

    def __init__(self, desired_item_status="SUCCESS"):
        self.desired_item_status = desired_item_status
        self.submit_calls = 0
        self.reconcile_batch_calls = 0
        self.reconcile_item_calls = 0

    def execute_payout(self, sender_batch_id, sender_item_id, recipient_email, amount_minor, currency):
        self.submit_calls += 1
        return {
            "payout_batch_id": f"mock_batch_{sender_batch_id}",
            "payout_item_id": f"mock_item_{sender_item_id}",
            "batch_status": "SUCCESS" if self.desired_item_status == "SUCCESS" else "PROCESSING",
            "item_status": self.desired_item_status,
            "response_redacted": "{\"mock\": true}",
        }

    def get_batch_status(self, payout_batch_id):
        self.reconcile_batch_calls += 1
        return {
            "batch_status": "SUCCESS" if self.desired_item_status == "SUCCESS" else "PROCESSING",
            "first_item_id": f"item_for_{payout_batch_id}",
            "first_item_status": self.desired_item_status,
        }

    def get_item_status(self, payout_item_id):
        self.reconcile_item_calls += 1
        return {
            "transaction_status": self.desired_item_status,
            "time_processed": utcnow().isoformat(),
        }


@pytest.fixture
def memory_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    create_immutability_triggers(engine)
    SessionFactory = sessionmaker(bind=engine)
    session = SessionFactory()
    yield session
    session.close()
    engine.dispose()


def test_gate2_rerun_idempotency_avoids_duplicate_payout(tmp_path, memory_db):
    """Confirm rerun with existing SUCCESS state does not create a new payout or intent."""
    state_file = tmp_path / ".gate2_state.json"
    evidence_file = tmp_path / "GATE2_EVIDENCE.md"

    asha, ravi = seed_default_users(memory_db)
    vendor, v1 = register_initial_vendor(
        session=memory_db,
        name="Acme Labs",
        trusted_contact_email="billing@acme.test",
        initial_paypal_recipient="v1@acme.test",
        requester_id=asha.id,
        approver_id=ravi.id,
        independent_contact_proof_type="CONTRACT_ON_FILE",
        proof_reference="GATE2-TEST-REF",
    )
    memory_db.commit()

    intent_id = f"pi_{uuid.uuid4().hex[:8]}"
    attempt_id = f"po_{uuid.uuid4().hex[:8]}"

    intent = PaymentIntent(
        id=intent_id,
        vendor_id=vendor.id,
        vendor_version_id=v1.id,
        amount_minor=100,
        currency="USD",
        invoice_reference="INV-TEST-001",
        requester_id=asha.id,
        state="SETTLED",
    )
    memory_db.add(intent)
    memory_db.flush()

    attempt = PayoutAttempt(
        id=attempt_id,
        payment_intent_id=intent.id,
        sender_batch_id="vt_batch_existing_001",
        sender_item_id=f"item_{intent.id}",
        state="SUCCESS",
        payout_batch_id="PAYPAL_BATCH_123",
        payout_item_id="PAYPAL_ITEM_456",
        amount_minor=100,
        currency="USD",
        resolved_recipient=v1.paypal_recipient,
    )
    memory_db.add(attempt)
    memory_db.commit()

    initial_intent_count = memory_db.query(PaymentIntent).count()
    initial_attempt_count = memory_db.query(PayoutAttempt).count()

    state = {
        "test_run_id": "test_run_001",
        "payment_intent_id": intent.id,
        "payout_attempt_id": attempt.id,
        "sender_batch_id": attempt.sender_batch_id,
        "payout_batch_id": attempt.payout_batch_id,
        "payout_item_id": attempt.payout_item_id,
        "status": "SUCCESS",
    }
    save_gate2_state(state, state_file)

    mock_adapter = MockSandboxAdapter(desired_item_status="SUCCESS")

    result = run_gate2(
        argv=[],
        db_session=memory_db,
        adapter=mock_adapter,
        state_file=state_file,
        evidence_file=evidence_file,
    )

    assert result is True
    # Zero network payout submissions
    assert mock_adapter.submit_calls == 0
    # Exactly same number of intents and attempts
    assert memory_db.query(PaymentIntent).count() == initial_intent_count
    assert memory_db.query(PayoutAttempt).count() == initial_attempt_count


def test_gate2_interrupted_run_resumes_reconciliation(tmp_path, memory_db):
    """Confirm that an in-flight or interrupted attempt is reconciled without a new submission."""
    state_file = tmp_path / ".gate2_state.json"
    evidence_file = tmp_path / "GATE2_EVIDENCE.md"

    asha, ravi = seed_default_users(memory_db)
    vendor, v1 = register_initial_vendor(
        session=memory_db,
        name="Acme Labs",
        trusted_contact_email="billing@acme.test",
        initial_paypal_recipient="v1@acme.test",
        requester_id=asha.id,
        approver_id=ravi.id,
        independent_contact_proof_type="CONTRACT_ON_FILE",
        proof_reference="GATE2-TEST-REF",
    )
    memory_db.commit()

    intent_id = f"pi_{uuid.uuid4().hex[:8]}"
    attempt_id = f"po_{uuid.uuid4().hex[:8]}"

    intent = PaymentIntent(
        id=intent_id,
        vendor_id=vendor.id,
        vendor_version_id=v1.id,
        amount_minor=100,
        currency="USD",
        invoice_reference="INV-TEST-RESUME",
        requester_id=asha.id,
        state="SUBMITTED",
    )
    memory_db.add(intent)
    memory_db.flush()

    attempt = PayoutAttempt(
        id=attempt_id,
        payment_intent_id=intent.id,
        sender_batch_id="vt_batch_interrupted_002",
        sender_item_id=f"item_{intent.id}",
        state="PENDING",
        payout_batch_id="BATCH_INTERRUPTED",
        payout_item_id="ITEM_INTERRUPTED",
        amount_minor=100,
        currency="USD",
        resolved_recipient=v1.paypal_recipient,
    )
    memory_db.add(attempt)
    memory_db.commit()

    state = {
        "test_run_id": "test_run_interrupted",
        "payment_intent_id": intent.id,
        "payout_attempt_id": attempt.id,
        "sender_batch_id": attempt.sender_batch_id,
        "payout_batch_id": attempt.payout_batch_id,
        "payout_item_id": attempt.payout_item_id,
        "status": "PENDING",
    }
    save_gate2_state(state, state_file)

    mock_adapter = MockSandboxAdapter(desired_item_status="SUCCESS")

    result = run_gate2(
        argv=[],
        db_session=memory_db,
        adapter=mock_adapter,
        state_file=state_file,
        evidence_file=evidence_file,
    )

    assert result is True
    # Reconciled via query, NEVER submitted as new payout
    assert mock_adapter.submit_calls == 0
    assert mock_adapter.reconcile_item_calls >= 1

    memory_db.refresh(attempt)
    memory_db.refresh(intent)
    assert attempt.state == "SUCCESS"
    assert intent.state == "SETTLED"

    updated_state = load_gate2_state(state_file)
    assert updated_state["status"] == "SUCCESS"


def test_gate2_uncertain_provider_response_reconciles_cleanly(tmp_path, memory_db):
    """Confirm that an uncertain response maintains safe pending status without resubmission."""
    state_file = tmp_path / ".gate2_state.json"
    evidence_file = tmp_path / "GATE2_EVIDENCE.md"

    asha, ravi = seed_default_users(memory_db)
    vendor, v1 = register_initial_vendor(
        session=memory_db,
        name="Acme Labs",
        trusted_contact_email="billing@acme.test",
        initial_paypal_recipient="v1@acme.test",
        requester_id=asha.id,
        approver_id=ravi.id,
        independent_contact_proof_type="CONTRACT_ON_FILE",
        proof_reference="GATE2-TEST-REF",
    )
    memory_db.commit()

    intent_id = f"pi_{uuid.uuid4().hex[:8]}"
    attempt_id = f"po_{uuid.uuid4().hex[:8]}"

    intent = PaymentIntent(
        id=intent_id,
        vendor_id=vendor.id,
        vendor_version_id=v1.id,
        amount_minor=100,
        currency="USD",
        invoice_reference="INV-UNCERTAIN",
        requester_id=asha.id,
        state="SUBMITTED",
    )
    memory_db.add(intent)
    memory_db.flush()

    attempt = PayoutAttempt(
        id=attempt_id,
        payment_intent_id=intent.id,
        sender_batch_id="vt_batch_uncertain_003",
        sender_item_id=f"item_{intent.id}",
        state="PENDING",
        payout_batch_id="BATCH_UNCERTAIN",
        payout_item_id="ITEM_UNCERTAIN",
        amount_minor=100,
        currency="USD",
        resolved_recipient=v1.paypal_recipient,
    )
    memory_db.add(attempt)
    memory_db.commit()

    state = {
        "test_run_id": "test_run_uncertain",
        "payment_intent_id": intent.id,
        "payout_attempt_id": attempt.id,
        "sender_batch_id": attempt.sender_batch_id,
        "payout_batch_id": attempt.payout_batch_id,
        "payout_item_id": attempt.payout_item_id,
        "status": "PENDING",
    }
    save_gate2_state(state, state_file)

    # Provider still reports PROCESSING
    mock_adapter = MockSandboxAdapter(desired_item_status="PROCESSING")

    result = run_gate2(
        argv=[],
        db_session=memory_db,
        adapter=mock_adapter,
        state_file=state_file,
        evidence_file=evidence_file,
    )

    assert result is False  # Pending / not yet SUCCESS
    assert mock_adapter.submit_calls == 0

    memory_db.refresh(attempt)
    assert attempt.state == "PENDING"
    assert intent.state == "SUBMITTED"


def test_gate2_force_new_test_requires_confirm_operator(tmp_path, memory_db):
    """Confirm '--force-new-test' fails closed with exit code 2 when '--confirm-operator' is missing."""
    state_file = tmp_path / ".gate2_state.json"
    evidence_file = tmp_path / "GATE2_EVIDENCE.md"

    with pytest.raises(SystemExit) as exc_info:
        run_gate2(
            argv=["--force-new-test"],
            db_session=memory_db,
            adapter=MockSandboxAdapter(),
            state_file=state_file,
            evidence_file=evidence_file,
        )
    assert exc_info.value.code == 2


def test_gate2_authorized_force_new_test_generates_unique_identity(tmp_path, memory_db):
    """Confirm that an authorized new test generates a distinct test run ID and sender batch ID."""
    state_file = tmp_path / ".gate2_state.json"
    evidence_file = tmp_path / "GATE2_EVIDENCE.md"

    mock_adapter = MockSandboxAdapter(desired_item_status="SUCCESS")

    result = run_gate2(
        argv=["--force-new-test", "--confirm-operator"],
        db_session=memory_db,
        adapter=mock_adapter,
        state_file=state_file,
        evidence_file=evidence_file,
    )

    assert result is True
    assert mock_adapter.submit_calls == 1

    saved_state = load_gate2_state(state_file)
    assert saved_state is not None
    assert saved_state["status"] == "SUCCESS"
    assert saved_state["test_run_id"].startswith("gate2_run_")
    assert saved_state["sender_batch_id"].startswith("vt_batch_")
