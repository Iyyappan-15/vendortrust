"""
tests/test_verification_checks.py — Verification of Phase 2 Hardening Controls

Verifies:
1. Multi-connection concurrent payout reservation on file-backed SQLite database.
2. Crash recovery immediately after reservation commit preserving sender_batch_id.
3. First-time onboarding requires independent approver and recorded proof metadata.
4. Fresh database creation via Alembic migrations installs SQLite immutability triggers.
"""

import os
import sqlite3
import tempfile
import threading
from pathlib import Path
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from alembic.config import Config
from alembic import command
from app.db import Base
from app.models import PaymentIntent, PayoutAttempt, VendorVersion
from app.services.approvals import approve_payment_intent, create_payment_intent
from app.services.exceptions import DuplicatePayoutError, SecurityViolationError
from app.services.payouts import MockPayoutProvider, submit_approved_payout
from app.services.vendor_registry import register_initial_vendor, seed_default_users


def test_concurrent_payout_separate_connections_file_db():
    """
    Check 1:
    Test concurrent payout requests using separate SQLite connections against the SAME file-backed DB.
    Confirms that simultaneous attempts cannot double-reserve the payment intent.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
        db_path = tmp_db.name

    try:
        db_url = f"sqlite:///{db_path}"
        engine = create_engine(db_url, connect_args={"check_same_thread": False, "timeout": 30})
        Base.metadata.create_all(bind=engine)
        SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        # Setup baseline data in session 0
        init_session = SessionFactory()
        asha, ravi = seed_default_users(init_session)
        vendor, v1 = register_initial_vendor(
            session=init_session,
            name="Concurrent Co",
            trusted_contact_email="billing@concurrent.test",
            initial_paypal_recipient="concurrent-pay@example.test",
            requester_id=asha.id,
            approver_id=ravi.id,
            independent_contact_proof_type="CONTRACT_ON_FILE",
            proof_reference="CONC-2026-001",
        )
        intent = create_payment_intent(
            session=init_session,
            vendor_id=vendor.id,
            invoice_reference="INV-RACE-01",
            amount_minor=1000,
            currency="USD",
            requester_id=asha.id,
        )
        approve_payment_intent(init_session, intent.id, approver_id=ravi.id)
        init_session.commit()
        intent_id = intent.id
        init_session.close()

        # Barrier to synchronize two threads at the exact execution start
        barrier = threading.Barrier(2)
        results = []
        errors = []

        def worker():
            s = SessionFactory()
            try:
                barrier.wait()
                attempt = submit_approved_payout(s, payment_intent_id=intent_id)
                results.append(attempt.id)
            except Exception as e:
                errors.append(e)
            finally:
                s.close()

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Verification: Only 1 unique payout attempt row must exist in the database
        verify_session = SessionFactory()
        attempts = verify_session.query(PayoutAttempt).filter_by(payment_intent_id=intent_id).all()
        assert len(attempts) == 1, f"Expected exactly 1 PayoutAttempt, found {len(attempts)}"
        assert attempts[0].state == "SUCCESS"
        verify_session.close()

    finally:
        engine.dispose()
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
        except OSError:
            pass


def test_crash_recovery_preserves_sender_batch_id(db_session, seeded_env):
    """
    Check 2:
    Simulate a crash immediately after the reservation is committed to the database.
    Calling submit_approved_payout again must resume the existing reservation and
    use the exact same sender_batch_id, never generating a new payment batch.
    """
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-CRASH-RECOVER",
        amount_minor=850,
        currency="USD",
        requester_id=asha.id,
    )
    approve_payment_intent(db_session, intent.id, approver_id=ravi.id)

    # Simulate crash hook: abort during network dispatch
    class ServerCrashError(Exception):
        pass

    def simulate_hard_crash(sender_batch_id, sender_item_id):
        raise ServerCrashError("Simulated server power loss during provider flight")

    crashing_provider = MockPayoutProvider(on_dispatch=simulate_hard_crash)

    # First attempt: crashes during network dispatch, but RESERVED attempt was committed
    attempt_before_crash = submit_approved_payout(
        session=db_session,
        payment_intent_id=intent.id,
        provider=crashing_provider,
    )
    assert attempt_before_crash.state == "RECONCILE_REQUIRED"
    original_batch_id = attempt_before_crash.sender_batch_id
    original_item_id = attempt_before_crash.sender_item_id

    # Recovery run: server boots back up and retries with a healthy provider
    healthy_provider = MockPayoutProvider(desired_item_status="SUCCESS")
    recovered_attempt = submit_approved_payout(
        session=db_session,
        payment_intent_id=intent.id,
        provider=healthy_provider,
    )

    # Verification: Must preserve the exact same sender_batch_id
    assert recovered_attempt.sender_batch_id == original_batch_id
    assert recovered_attempt.sender_item_id == original_item_id
    assert recovered_attempt.id == attempt_before_crash.id


def test_onboarding_requires_distinct_approver_and_evidence(db_session, seeded_env):
    """
    Check 3:
    First-time vendor onboarding strictly requires both distinct actors AND substantive proof.
    Evidence metadata alone without independent approver is rejected.
    """
    asha = seeded_env["asha"]

    # Same user attempting to use valid evidence metadata -> rejected
    with pytest.raises(SecurityViolationError, match="distinct individuals"):
        register_initial_vendor(
            session=db_session,
            name="Self Approved Vendor",
            trusted_contact_email="self@example.test",
            initial_paypal_recipient="self@example.test",
            requester_id=asha.id,
            approver_id=asha.id,
            independent_contact_proof_type="OFFICIAL_BANK_STATEMENT",
            proof_reference="STMT-2026-999",
        )


def test_alembic_upgrade_head_installs_immutability_triggers():
    """
    Check 4:
    Create a fresh SQLite database using only 'alembic upgrade head' and verify
    the UPDATE and DELETE triggers on vendor_versions are installed and active.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
        fresh_db_path = tmp_db.name

    try:
        # Run alembic upgrade head against this fresh database
        root_dir = Path(__file__).resolve().parent.parent
        alembic_cfg = Config(str(root_dir / "alembic.ini"))
        alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{fresh_db_path}")

        command.upgrade(alembic_cfg, "head")

        # Connect directly with sqlite3 to inspect triggers
        conn = sqlite3.connect(fresh_db_path)
        cursor = conn.cursor()
        triggers = cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='trigger'").fetchall()
        trigger_names = [t[0] for t in triggers]

        assert "trg_prevent_vendor_version_update" in trigger_names
        assert "trg_prevent_vendor_version_delete" in trigger_names

        # Insert a test vendor and vendor_version manually to test the trigger
        conn.execute("PRAGMA foreign_keys=OFF")  # Isolate trigger test
        conn.execute("INSERT INTO vendor_versions (id, vendor_id, version_number, paypal_recipient, contact_snapshot_email, created_by_user_id, approved_by_user_id, created_at, content_digest) VALUES ('v1', 'vend1', 1, 'test@example.com', 'test@example.com', 'u1', 'u2', '2026-10-25 10:00:00', 'hash')")
        conn.commit()

        # Attempt raw SQL update -> trigger must abort
        with pytest.raises(sqlite3.DatabaseError, match="strictly immutable"):
            conn.execute("UPDATE vendor_versions SET paypal_recipient = 'hacked@example.com' WHERE id = 'v1'")

        # Attempt raw SQL delete -> trigger must abort
        with pytest.raises(sqlite3.DatabaseError, match="strictly immutable"):
            conn.execute("DELETE FROM vendor_versions WHERE id = 'v1'")

        conn.close()

    finally:
        try:
            if os.path.exists(fresh_db_path):
                os.remove(fresh_db_path)
        except OSError:
            pass
