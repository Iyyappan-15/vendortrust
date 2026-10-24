"""
app/services/audit.py — Append-only Audit Service
"""

import hashlib
import json
import uuid
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from app.models import AuditEvent, utcnow


def compute_evidence_digest(entity_type: str, entity_id: str, state_before: Optional[str], state_after: Optional[str], details: Optional[Dict[str, Any]] = None) -> str:
    raw = f"{entity_type}:{entity_id}:{state_before or 'NONE'}:{state_after or 'NONE'}:{json.dumps(details or {}, sort_keys=True)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def record_audit_event(
    session: Session,
    event_type: str,
    entity_type: str,
    entity_id: str,
    actor_id: Optional[str] = None,
    state_before: Optional[str] = None,
    state_after: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    """
    Append-only recording of security-critical state transitions and decisions.
    """
    digest = compute_evidence_digest(entity_type, entity_id, state_before, state_after, details)
    event = AuditEvent(
        id=str(uuid.uuid4()),
        event_type=event_type,
        actor_id=actor_id,
        entity_type=entity_type,
        entity_id=entity_id,
        state_before=state_before,
        state_after=state_after,
        evidence_digest=digest,
        details_json=json.dumps(details) if details else None,
        created_at=utcnow(),
    )
    session.add(event)
    return event
