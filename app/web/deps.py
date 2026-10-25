"""
app/web/deps.py — FastAPI dependency injection for demo and private session handling.
"""
from typing import Optional, Tuple
from fastapi import Cookie, Request, HTTPException
from sqlalchemy.orm import Session

from app.config import OPERATOR_API_KEY
from app.web.session import get_demo_session_db, new_demo_session


class DemoContext:
    """Carries the per-demo-session database and user identity data."""
    def __init__(self, db: Session, meta: dict):
        self.db = db
        self.asha_id: str = meta["asha_id"]
        self.ravi_id: str = meta["ravi_id"]
        self.vendor_id: str = meta["vendor_id"]
        self.v1_id: str = meta["v1_id"]


def require_demo_context(demo_session: Optional[str] = Cookie(None)) -> DemoContext:
    """FastAPI dep: resolve or raise for PUBLIC_DEMO mode sessions."""
    if not demo_session:
        raise HTTPException(status_code=403, detail="No demo session. Visit / to start.")
    db, meta = get_demo_session_db(demo_session)
    if db is None:
        raise HTTPException(status_code=403, detail="Demo session expired. Visit / to restart.")
    return DemoContext(db=db, meta=meta)
