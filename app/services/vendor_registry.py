"""
app/services/vendor_registry.py — Vendor Registry, Immutable Versions, and Seed Identities
"""

import hashlib
import uuid
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from app.models import User, Vendor, VendorVersion, utcnow
from app.services.audit import record_audit_event
from app.services.exceptions import SecurityViolationError, VendorFrozenError

# Canonical Seeded User IDs
REQUESTER_ASHA_ID = "user_requester_asha_001"
APPROVER_RAVI_ID = "user_approver_ravi_002"


def seed_default_users(session: Session) -> Tuple[User, User]:
    """
    Seed Asha (Requester) and Ravi (Approver).
    Note: These personas are demonstration fixtures to test separation of duties.
    They do NOT represent public production authentication.
    """
    asha = session.query(User).filter_by(id=REQUESTER_ASHA_ID).first()
    if not asha:
        asha = User(
            id=REQUESTER_ASHA_ID,
            display_name="Asha (Requester)",
            email="asha.requester@agency.test",
            role="REQUESTER",
            is_active=True,
            demo_only=True,
            created_at=utcnow(),
        )
        session.add(asha)

    ravi = session.query(User).filter_by(id=APPROVER_RAVI_ID).first()
    if not ravi:
        ravi = User(
            id=APPROVER_RAVI_ID,
            display_name="Ravi (Approver)",
            email="ravi.approver@agency.test",
            role="APPROVER",
            is_active=True,
            demo_only=True,
            created_at=utcnow(),
        )
        session.add(ravi)

    session.flush()
    return asha, ravi


def compute_vendor_version_digest(
    vendor_id: str,
    version_number: int,
    paypal_recipient: str,
    contact_snapshot_email: str,
) -> str:
    """Compute deterministic SHA-256 digest of immutable vendor version contents."""
    raw = f"{vendor_id}:{version_number}:{paypal_recipient.strip().lower()}:{contact_snapshot_email.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def register_initial_vendor(
    session: Session,
    name: str,
    trusted_contact_email: str,
    initial_paypal_recipient: str,
    requester_id: str,
    approver_id: str,
    vendor_id: Optional[str] = None,
) -> Tuple[Vendor, VendorVersion]:
    """
    Initial onboarding of a trusted vendor.
    Enforces separation of duties: requester cannot be the approver who activates the vendor.
    The trusted contact is READ-ONLY in MVP and recorded as the baseline for all future challenges.
    """
    if requester_id == approver_id:
        raise SecurityViolationError("Requester and approver must be distinct individuals during vendor onboarding.")

    # Validate approver has APPROVER role
    approver = session.query(User).filter_by(id=approver_id).first()
    if not approver or approver.role != "APPROVER":
        raise SecurityViolationError(f"User {approver_id} does not hold the APPROVER role.")

    vid = vendor_id or str(uuid.uuid4())
    version_id = str(uuid.uuid4())

    digest = compute_vendor_version_digest(
        vendor_id=vid,
        version_number=1,
        paypal_recipient=initial_paypal_recipient,
        contact_snapshot_email=trusted_contact_email,
    )

    vendor = Vendor(
        id=vid,
        name=name,
        trusted_contact_email=trusted_contact_email.strip().lower(),
        active_version_id=None,
        status="ACTIVE",
        created_at=utcnow(),
    )
    session.add(vendor)
    session.flush()

    v1 = VendorVersion(
        id=version_id,
        vendor_id=vid,
        version_number=1,
        paypal_recipient=initial_paypal_recipient.strip().lower(),
        contact_snapshot_email=trusted_contact_email.strip().lower(),
        verification_case_id=None,
        created_by_user_id=requester_id,
        approved_by_user_id=approver_id,
        created_at=utcnow(),
        superseded_at=None,
        content_digest=digest,
    )
    session.add(v1)
    session.flush()

    vendor.active_version_id = version_id
    session.flush()

    record_audit_event(
        session=session,
        event_type="VENDOR_ONBOARDED",
        actor_id=approver_id,
        entity_type="VENDOR",
        entity_id=vid,
        state_before=None,
        state_after="ACTIVE",
        details={
            "vendor_name": name,
            "trusted_contact": trusted_contact_email,
            "initial_recipient": initial_paypal_recipient,
            "version_id": version_id,
            "requester_id": requester_id,
            "approver_id": approver_id,
        },
    )

    return vendor, v1


def get_vendor(session: Session, vendor_id: str) -> Vendor:
    """Fetch vendor by ID or raise error if not found."""
    vendor = session.query(Vendor).filter_by(id=vendor_id).first()
    if not vendor:
        raise ValueError(f"Vendor '{vendor_id}' not found.")
    return vendor


def check_vendor_active(vendor: Vendor) -> None:
    """Verify vendor is active and not frozen under compromise suspicion."""
    if vendor.status == "FROZEN_SUSPECTED_COMPROMISE":
        raise VendorFrozenError(f"Vendor '{vendor.id}' ({vendor.name}) is FROZEN due to suspected compromise.")


def freeze_vendor(session: Session, vendor_id: str, actor_id: Optional[str], reason: str) -> Vendor:
    """Freeze a vendor permanently under compromise suspicion (no auto-unfreeze)."""
    vendor = get_vendor(session, vendor_id)
    prev_status = vendor.status
    vendor.status = "FROZEN_SUSPECTED_COMPROMISE"

    record_audit_event(
        session=session,
        event_type="VENDOR_FROZEN_COMPROMISE",
        actor_id=actor_id,
        entity_type="VENDOR",
        entity_id=vendor_id,
        state_before=prev_status,
        state_after="FROZEN_SUSPECTED_COMPROMISE",
        details={"reason": reason},
    )
    return vendor
