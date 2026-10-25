"""
app/web/deps.py — FastAPI dependency injection for demo session and CSRF security.
"""
from typing import Optional
from fastapi import Cookie, Form, HTTPException, Request
from sqlalchemy.orm import Session

from app.web.session import get_demo_session_db, validate_csrf_token


class DemoContext:
    """Carries the per-demo-session database, user identity, and session CSRF token."""
    def __init__(self, db: Session, meta: dict, session_token: str):
        self.db = db
        self.session_token = session_token
        self.asha_id: str = meta["asha_id"]
        self.ravi_id: str = meta["ravi_id"]
        self.vendor_id: str = meta["vendor_id"]
        self.v1_id: str = meta["v1_id"]
        self.csrf_token: str = meta.get("csrf_token", "")


def require_demo_context(demo_session: Optional[str] = Cookie(None)) -> DemoContext:
    """FastAPI dep: resolve or raise for PUBLIC_DEMO mode sessions."""
    if not demo_session:
        raise HTTPException(status_code=403, detail="No demo session. Visit / to start.")
    db, meta = get_demo_session_db(demo_session)
    if db is None:
        raise HTTPException(status_code=403, detail="Demo session expired. Visit / to restart.")
    return DemoContext(db=db, meta=meta, session_token=demo_session)


def assert_csrf(ctx: DemoContext, submitted_csrf: Optional[str]) -> None:
    """Enforces constant-time CSRF token check on state-changing browser routes."""
    if not validate_csrf_token(ctx.session_token, submitted_csrf):
        raise HTTPException(status_code=403, detail="CSRF token validation failed. Request rejected.")
