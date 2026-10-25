"""
app/web/session.py — Per-session demo database management for PUBLIC_DEMO mode.

Each browser session in PUBLIC_DEMO mode gets an isolated in-memory SQLite database
pre-seeded with demo data. This guarantees complete isolation between public visitors.

Resource & Security Hardening:
- Configurable TTL (2 hours) and bounded session limit (100)
- Automatic cleanup of expired sessions and explicit engine.dispose() resource reclamation
- Cryptographically secure per-session CSRF token generation and validation
"""
import secrets
import threading
import time
from typing import Dict, Any, Optional, Tuple
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, create_immutability_triggers
from app.services.vendor_registry import seed_default_users, register_initial_vendor

# Session limits & TTL controls
SESSION_TTL_SECONDS = 7200  # 2 hours
MAX_ACTIVE_SESSIONS = 100

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


def _cleanup_expired_sessions_locked():
    """Internal helper: dispose expired engines and prune sessions. Must hold _store_lock."""
    now = time.time()
    expired_keys = [
        k for k, v in _demo_store.items()
        if now - v.get("last_accessed_at", 0) > SESSION_TTL_SECONDS
    ]
    for k in expired_keys:
        data = _demo_store.pop(k, None)
        if data and "engine" in data:
            try:
                data["engine"].dispose()
            except Exception:
                pass

    # If still exceeding capacity, evict oldest sessions
    if len(_demo_store) >= MAX_ACTIVE_SESSIONS:
        sorted_keys = sorted(_demo_store.keys(), key=lambda k: _demo_store[k].get("last_accessed_at", 0))
        excess = len(_demo_store) - MAX_ACTIVE_SESSIONS + 1
        for k in sorted_keys[:excess]:
            data = _demo_store.pop(k, None)
            if data and "engine" in data:
                try:
                    data["engine"].dispose()
                except Exception:
                    pass


def new_demo_session() -> str:
    """Create a fresh isolated demo session with bounded capacity. Returns opaque session token."""
    with _store_lock:
        _cleanup_expired_sessions_locked()

    token = secrets.token_urlsafe(24)
    csrf_token = secrets.token_urlsafe(32)
    engine = _make_demo_engine()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    asha, ravi, vendor, v1 = _seed_demo(db)
    now = time.time()

    with _store_lock:
        _demo_store[token] = {
            "engine": engine,
            "SessionLocal": SessionLocal,
            "asha_id": asha.id,
            "ravi_id": ravi.id,
            "vendor_id": vendor.id,
            "v1_id": v1.id,
            "csrf_token": csrf_token,
            "created_at": now,
            "last_accessed_at": now,
        }
    return token


def get_demo_session_db(token: str) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
    """Return (db_session, meta_dict) for valid demo token. Disposes and returns (None, None) if expired."""
    now = time.time()
    with _store_lock:
        data = _demo_store.get(token)
        if not data:
            return None, None

        if now - data.get("last_accessed_at", 0) > SESSION_TTL_SECONDS:
            # Expired: dispose engine and prune
            _demo_store.pop(token, None)
            try:
                data["engine"].dispose()
            except Exception:
                pass
            return None, None

        data["last_accessed_at"] = now

    db = data["SessionLocal"]()
    return db, data


def destroy_demo_session(token: str) -> None:
    """Explicitly destroy session and dispose underlying engine resources."""
    with _store_lock:
        data = _demo_store.pop(token, None)
        if data and "engine" in data:
            try:
                data["engine"].dispose()
            except Exception:
                pass


def validate_csrf_token(token: str, submitted_csrf: Optional[str]) -> bool:
    """Constant-time validation of CSRF token bound to demo session."""
    if not submitted_csrf or not token:
        return False
    with _store_lock:
        data = _demo_store.get(token)
        if not data:
            return False
        expected_csrf = data.get("csrf_token")
    if not expected_csrf:
        return False
    return secrets.compare_digest(submitted_csrf.strip(), expected_csrf.strip())
