"""
tests/test_versions.py — Tests for Vendor Version Immutability and Version Transitions
"""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.models import VendorVersion
from app.services.approvals import approve_payee_change_case
from app.services.challenges import (
    create_payee_change_case,
    issue_verification_challenge,
    verify_vendor_confirmation,
)
from app.services.exceptions import SecurityViolationError
from app.services.vendor_registry import compute_vendor_version_digest


def test_immutable_vendor_version_creation(db_session, seeded_env):
    """Confirming and approving a payee change creates version N+1 without modifying N."""
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]
    v1 = seeded_env["v1"]

    assert v1.version_number == 1
    assert vendor.active_version_id == v1.id

    # Create and confirm payee change case
    case = create_payee_change_case(
        session=db_session,
        vendor_id=vendor.id,
        proposed_recipient="verified-v2@example.test",
        source_type="INVOICE_PROPOSAL",
        source_reference="INV-V2",
        requester_id=asha.id,
    )
    _, token = issue_verification_challenge(db_session, case.id)
    verify_vendor_confirmation(db_session, case.id, token)

    # Approver Ravi approves the case
    case, v2 = approve_payee_change_case(db_session, case.id, approver_id=ravi.id)

    db_session.refresh(vendor)
    db_session.refresh(v1)

    # Invariants
    assert v2.version_number == 2
    assert v2.paypal_recipient == "verified-v2@example.test"
    assert v2.contact_snapshot_email == vendor.trusted_contact_email
    assert v2.content_digest == compute_vendor_version_digest(
        vendor.id, 2, "verified-v2@example.test", vendor.trusted_contact_email
    )

    # Version 1 remains 100% intact, immutable, and is no longer active
    assert v1.version_number == 1
    assert v1.paypal_recipient == "acme-pay@example.test"
    assert vendor.active_version_id == v2.id
    assert vendor.active_version_id != v1.id


def test_version_number_uniqueness_constraint(db_session, seeded_env):
    """The database schema prevents inserting duplicate (vendor_id, version_number) records."""
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    vendor = seeded_env["vendor"]

    duplicate_v1 = VendorVersion(
        id="duplicate_version_id",
        vendor_id=vendor.id,
        version_number=1,  # Duplicate version 1
        paypal_recipient="duplicate@example.test",
        contact_snapshot_email="duplicate@example.test",
        verification_case_id=None,
        created_by_user_id=asha.id,
        approved_by_user_id=ravi.id,
        content_digest="dummy_digest",
    )
    db_session.add(duplicate_v1)

    with pytest.raises(IntegrityError):
        db_session.commit()


def test_direct_orm_modification_of_vendor_version_blocked(db_session, seeded_env):
    """Attempting to mutate an existing VendorVersion row via ORM is blocked by immutability hooks."""
    v1 = seeded_env["v1"]

    v1.paypal_recipient = "malicious-overwrite@example.test"
    with pytest.raises(SecurityViolationError, match="strictly immutable"):
        db_session.flush()


def test_direct_sql_modification_of_vendor_version_blocked_by_trigger(db_session, seeded_env):
    """Attempting raw SQL UPDATE on vendor_versions is rejected by database trigger."""
    v1 = seeded_env["v1"]

    with pytest.raises(Exception, match="strictly immutable|VendorVersion"):
        db_session.execute(
            text("UPDATE vendor_versions SET paypal_recipient = 'injected@example.test' WHERE id = :vid"),
            {"vid": v1.id},
        )
        db_session.commit()


def test_direct_deletion_of_vendor_version_blocked(db_session, seeded_env):
    """Attempting to delete a VendorVersion row via ORM is blocked."""
    v1 = seeded_env["v1"]

    db_session.delete(v1)
    with pytest.raises(SecurityViolationError, match="cannot be deleted"):
        db_session.flush()
