"""
app/db.py — Database Engine, Session Management, and SQLite Pragmas & Triggers
"""

from typing import Generator
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.config import DATABASE_URL

# Enforce foreign key constraints and timeout in SQLite
@event.listens_for(Engine, "connect")
def configure_sqlite(dbapi_connection, connection_record):
    if hasattr(dbapi_connection, "cursor"):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
        finally:
            cursor.close()


def create_immutability_triggers(target_engine):
    """Create SQLite database-level triggers to enforce immutability on vendor_versions."""
    with target_engine.begin() as conn:
        conn.execute(text("""
            CREATE TRIGGER IF NOT EXISTS trg_prevent_vendor_version_update
            BEFORE UPDATE ON vendor_versions
            BEGIN
                SELECT RAISE(ABORT, 'VendorVersion rows are strictly immutable and cannot be updated.');
            END;
        """))
        conn.execute(text("""
            CREATE TRIGGER IF NOT EXISTS trg_prevent_vendor_version_delete
            BEFORE DELETE ON vendor_versions
            BEGIN
                SELECT RAISE(ABORT, 'VendorVersion rows are strictly immutable and cannot be deleted.');
            END;
        """))


connect_args = {}
if "sqlite" in DATABASE_URL:
    connect_args["check_same_thread"] = False
    connect_args["timeout"] = 30

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False,
    future=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Dependency / generator for acquiring a database session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
