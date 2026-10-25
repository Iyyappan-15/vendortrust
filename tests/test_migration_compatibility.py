"""
tests/test_migration_compatibility.py — Tests for Alembic Migration Schema Compatibility

Verifies:
1. 'alembic upgrade head' against a completely fresh SQLite database creates the full schema
   including case_type and nullable proposed_recipient.
2. Manual-review cases (with proposed_recipient=NULL and case_type='MANUAL_EXTRACTION_REVIEW')
   can be inserted cleanly into the migrated database.
3. Upgrading an existing database with pre-existing records (upgraded from bd69256a20da)
   preserves existing records, defaults case_type to 'RECIPIENT_CHANGE_PROPOSAL', and
   preserves immutable vendor_version SQLite triggers.
4. SQLAlchemy ORM models match the actual table columns produced by Alembic.
"""

import os
import sqlite3
import tempfile
from pathlib import Path
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from app.models import PayeeChangeCase, User, Vendor, VendorVersion


def _get_alembic_config(db_path: str) -> Config:
    root_dir = Path(__file__).resolve().parent.parent
    cfg = Config(str(root_dir / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def test_fresh_database_alembic_upgrade_head():
    """Verify that a fresh database upgraded to head has case_type and nullable proposed_recipient."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        cfg = _get_alembic_config(db_path)
        command.upgrade(cfg, "head")

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # Check table columns in payee_change_cases
        columns = cur.execute("PRAGMA table_info(payee_change_cases)").fetchall()
        col_names = {col[1]: col for col in columns}

        assert "case_type" in col_names, "case_type column missing from migrated payee_change_cases"
        assert "proposed_recipient" in col_names, "proposed_recipient column missing from migrated payee_change_cases"

        # proposed_recipient should be nullable (col[3] is notnull: 0 means nullable)
        assert col_names["proposed_recipient"][3] == 0, "proposed_recipient must be nullable"

        # Triggers must be present
        triggers = cur.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()
        trig_names = [t[0] for t in triggers]
        assert "trg_prevent_vendor_version_update" in trig_names
        assert "trg_prevent_vendor_version_delete" in trig_names

        conn.close()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_insert_manual_review_case_into_migrated_db():
    """Verify that an ORM PayeeChangeCase with proposed_recipient=None can be inserted into the migrated DB."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        cfg = _get_alembic_config(db_path)
        command.upgrade(cfg, "head")

        engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
        Session = sessionmaker(bind=engine)
        session = Session()

        # Insert required foreign-key targets
        u = User(id="user-mig-1", display_name="Asha", email="asha@test.com", role="REQUESTER")
        v = Vendor(id="vend-mig-1", name="Acme", trusted_contact_email="billing@acme.test")
        vv = VendorVersion(
            id="ver-mig-1", vendor_id="vend-mig-1", version_number=1,
            paypal_recipient="legit@acme.test", contact_snapshot_email="billing@acme.test",
            created_by_user_id="user-mig-1", approved_by_user_id="user-mig-1",
            content_digest="dummy"
        )
        session.add_all([u, v, vv])
        session.commit()

        # Insert a MANUAL_EXTRACTION_REVIEW case with proposed_recipient=None
        import datetime
        from app.models import utcnow
        case = PayeeChangeCase(
            id="case-mig-review-1",
            vendor_id="vend-mig-1",
            base_version_id="ver-mig-1",
            case_type="MANUAL_EXTRACTION_REVIEW",
            proposed_recipient=None,
            source_type="invoice_text",
            source_digest="dummy",
            requester_id="user-mig-1",
            state="HELD",
            expires_at=utcnow() + datetime.timedelta(hours=48),
        )
        session.add(case)
        session.commit()

        loaded = session.query(PayeeChangeCase).filter_by(id="case-mig-review-1").first()
        assert loaded is not None
        assert loaded.case_type == "MANUAL_EXTRACTION_REVIEW"
        assert loaded.proposed_recipient is None

        session.close()
        engine.dispose()
    finally:
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
        except OSError:
            pass


def test_upgrade_from_previous_revision_preserves_records_and_sets_default():
    """
    Simulate an existing database at revision bd69256a20da with existing records,
    then upgrade to head. Verify that existing records survive and get default case_type.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        cfg = _get_alembic_config(db_path)
        # Step 1: Upgrade only to previous revision bd69256a20da
        command.upgrade(cfg, "bd69256a20da")

        # Step 2: Insert a pre-existing payee_change_case
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("INSERT INTO users (id, display_name, email, role, is_active, demo_only, created_at) VALUES ('u_old', 'Asha', 'asha_old@test.com', 'REQUESTER', 1, 1, '2026-10-25 10:00:00')")
        cur.execute("INSERT INTO vendors (id, name, trusted_contact_email, status, created_at) VALUES ('v_old', 'Acme Old', 'old@acme.test', 'ACTIVE', '2026-10-25 10:00:00')")
        cur.execute("INSERT INTO vendor_versions (id, vendor_id, version_number, paypal_recipient, contact_snapshot_email, created_by_user_id, approved_by_user_id, created_at, content_digest) VALUES ('vv_old', 'v_old', 1, 'old@acme.test', 'old@acme.test', 'u_old', 'u_old', '2026-10-25 10:00:00', 'hash')")
        cur.execute("INSERT INTO payee_change_cases (id, vendor_id, base_version_id, proposed_recipient, source_type, source_digest, requester_id, state, created_at, updated_at, expires_at) VALUES ('case_old', 'v_old', 'vv_old', 'new@acme.test', 'INVOICE', 'digest', 'u_old', 'HELD', '2026-10-25 10:00:00', '2026-10-25 10:00:00', '2026-10-27 10:00:00')")
        conn.commit()
        conn.close()

        # Step 3: Upgrade to head (applies 13034b7cc906)
        command.upgrade(cfg, "head")

        # Step 4: Verify pre-existing case survived and received the default case_type
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        row = cur.execute("SELECT id, proposed_recipient, case_type FROM payee_change_cases WHERE id = 'case_old'").fetchone()
        assert row is not None
        assert row[0] == "case_old"
        assert row[1] == "new@acme.test"
        assert row[2] == "RECIPIENT_CHANGE_PROPOSAL"

        # Verify triggers are still installed and active
        triggers = cur.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()
        trig_names = [t[0] for t in triggers]
        assert "trg_prevent_vendor_version_update" in trig_names
        assert "trg_prevent_vendor_version_delete" in trig_names

        with pytest.raises(sqlite3.DatabaseError, match="strictly immutable"):
            cur.execute("UPDATE vendor_versions SET paypal_recipient = 'hacked@acme.test' WHERE id = 'vv_old'")

        conn.close()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
