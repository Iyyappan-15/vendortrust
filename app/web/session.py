"""
app/web/session.py — Per-session demo database management for PUBLIC_DEMO mode.

Each browser session in PUBLIC_DEMO mode gets an isolated in-memory SQLite database
pre-seeded with demo data. This guarantees complete isolation between public visitors.
"""
import secrets
import threading
from typing import Dict, Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, create_immutability_triggers
from app.services.vendor_registry import seed_default_users, register_initial_vendor

# Thread-safe session store keyed by session token
_demo_store: Dict[str, Any] = {}
_store_lock = threading.Lock()

DEMO_VENDOR_RECIPIENT = "acme-billing@acme-design.test"
DEMO_TRUSTED_EMAIL = "billing@acme-design.test"


def _make_demo_engine():
    """Create a fresh isolated in-memory SQLite engine for one demo session."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    from sqlalchemy import event as sqla_event

    @sqla_event.listens_for(engine, "connect")
    def set_pragma(conn, _):
        cur = conn.cursor()
        try:
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA busy_timeout=10000")
        finally:
            cur.close()

    Base.metadata.create_all(bind=engine)
    create_immutability_triggers(engine)
    return engine


def _seed_demo(session):
    """Seed users and an initial demo vendor into a fresh session."""
    asha, ravi = seed_default_users(session)
    vendor, v1 = register_initial_vendor(
        session=session,
        name="Acme Design Labs",
        trusted_contact_email=DEMO_TRUSTED_EMAIL,
        initial_paypal_recipient=DEMO_VENDOR_RECIPIENT,
        requester_id=asha.id,
        approver_id=ravi.id,
        independent_contact_proof_type="CONTRACT_ON_FILE",
        proof_reference="MASTER-MSA-DEMO-001",
    )
    session.commit()
    return asha, ravi, vendor, v1


def new_demo_session() -> str:
    """Create a fresh isolated demo session. Returns an opaque session token."""
    token = secrets.token_urlsafe(24)
    engine = _make_demo_engine()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    asha, ravi, vendor, v1 = _seed_demo(db)
    with _store_lock:
        _demo_store[token] = {
            "engine": engine,
            "SessionLocal": SessionLocal,
            "asha_id": asha.id,
            "ravi_id": ravi.id,
            "vendor_id": vendor.id,
            "v1_id": v1.id,
        }
    return token


def get_demo_session_db(token: str):
    """Return (db_session, meta_dict) for the given demo token, or (None, None) if expired."""
    with _store_lock:
        data = _demo_store.get(token)
    if not data:
        return None, None
    db = data["SessionLocal"]()
    return db, data


def destroy_demo_session(token: str):
    with _store_lock:
        _demo_store.pop(token, None)
