"""
tests/conftest.py — Test Fixtures and In-Memory SQLite Setup
"""

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from app.db import Base
from app.services.vendor_registry import (
    APPROVER_RAVI_ID,
    REQUESTER_ASHA_ID,
    register_initial_vendor,
    seed_default_users,
)


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if hasattr(dbapi_connection, "cursor"):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()


@pytest.fixture(scope="function")
def db_session() -> Session:
    """Create an isolated in-memory SQLite database for each test function."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture(scope="function")
def seeded_env(db_session: Session):
    """Provides seeded users Asha (Requester) and Ravi (Approver) plus an initial active vendor."""
    asha, ravi = seed_default_users(db_session)
    vendor, v1 = register_initial_vendor(
        session=db_session,
        name="Acme Design Labs",
        trusted_contact_email="billing@acme-design.test",
        initial_paypal_recipient="acme-pay@example.test",
        requester_id=asha.id,
        approver_id=ravi.id,
    )
    db_session.commit()
    return {
        "session": db_session,
        "asha": asha,
        "ravi": ravi,
        "vendor": vendor,
        "v1": v1,
    }
