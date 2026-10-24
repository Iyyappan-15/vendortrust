"""
app/models.py — Core SQLAlchemy Models for VendorTrust

Implements the nine core tables:
1. users
2. vendors
3. vendor_versions
4. payee_change_cases
5. verification_challenges
6. approvals
7. payment_intents
8. payout_attempts
9. audit_events
"""

import datetime
from typing import Optional
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import relationship
from app.db import Base


def utcnow() -> datetime.datetime:
    """Return timezone-naive UTC timestamp for consistent SQLite compatibility."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class User(Base):
    """
    Seeded identities (e.g. Asha the requester, Ravi the approver).
    Public demo role switching is a simulation only, never live authentication.
    """
    __tablename__ = "users"

    id = Column(String(36), primary_key=True)
    display_name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    role = Column(String(50), nullable=False)  # REQUESTER, APPROVER, OPERATOR
    is_active = Column(Boolean, default=True, nullable=False)
    demo_only = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<User {self.display_name} ({self.role})>"


class Vendor(Base):
    """
    Vendor master entity.
    The trusted contact is READ-ONLY in MVP and immutable after bootstrap.
    """
    __tablename__ = "vendors"

    id = Column(String(36), primary_key=True)
    name = Column(String(150), nullable=False, index=True)
    trusted_contact_email = Column(String(255), nullable=False)  # Immutable in MVP
    active_version_id = Column(
        String(36),
        ForeignKey("vendor_versions.id", use_alter=True, name="fk_vendor_active_version"),
        nullable=True,
    )
    status = Column(String(50), default="ACTIVE", nullable=False)  # ACTIVE, FROZEN_SUSPECTED_COMPROMISE
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    active_version = relationship("VendorVersion", foreign_keys=[active_version_id], post_update=True)
    versions = relationship("VendorVersion", back_populates="vendor", foreign_keys="VendorVersion.vendor_id")
    change_cases = relationship("PayeeChangeCase", back_populates="vendor")

    def __repr__(self) -> str:
        return f"<Vendor {self.name} (Status: {self.status})>"


class VendorVersion(Base):
    """
    Immutable vendor version records.
    Never update or delete an existing version record. When a change is approved,
    version N+1 is created transactionally and version N is superseded.
    """
    __tablename__ = "vendor_versions"

    id = Column(String(36), primary_key=True)
    vendor_id = Column(String(36), ForeignKey("vendors.id", ondelete="RESTRICT"), nullable=False, index=True)
    version_number = Column(Integer, nullable=False)
    paypal_recipient = Column(String(255), nullable=False)
    contact_snapshot_email = Column(String(255), nullable=False)
    verification_case_id = Column(String(36), nullable=True)  # Null for initial bootstrap
    created_by_user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    approved_by_user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    superseded_at = Column(DateTime(timezone=True), nullable=True)
    content_digest = Column(String(64), nullable=False)  # SHA-256 of version content

    __table_args__ = (
        UniqueConstraint("vendor_id", "version_number", name="uq_vendor_version_number"),
    )

    vendor = relationship("Vendor", back_populates="versions", foreign_keys=[vendor_id])
    created_by = relationship("User", foreign_keys=[created_by_user_id])
    approved_by = relationship("User", foreign_keys=[approved_by_user_id])

    def __repr__(self) -> str:
        return f"<VendorVersion v{self.version_number} for Vendor {self.vendor_id} -> {self.paypal_recipient}>"


class PayeeChangeCase(Base):
    """
    Tracks a proposed change to a vendor's PayPal recipient.
    Starts in HELD status. Can never authorize a change directly.
    """
    __tablename__ = "payee_change_cases"

    id = Column(String(36), primary_key=True)
    vendor_id = Column(String(36), ForeignKey("vendors.id", ondelete="RESTRICT"), nullable=False, index=True)
    base_version_id = Column(String(36), ForeignKey("vendor_versions.id"), nullable=False)
    proposed_recipient = Column(String(255), nullable=False)
    source_type = Column(String(50), nullable=False)  # INVOICE_PROPOSAL, MANUAL_PROPOSAL, EMAIL_EXTRACT
    source_digest = Column(String(64), nullable=False)
    requester_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    state = Column(
        String(50),
        default="HELD",
        nullable=False,
        index=True,
    )  # HELD, CHALLENGE_ISSUED, VENDOR_CONFIRMED, APPROVER_APPROVED, VERSION_ACTIVATED, REJECTED_COMPROMISE_SUSPECTED, REJECTED, EXPIRED
    rejection_reason = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    vendor = relationship("Vendor", back_populates="change_cases")
    base_version = relationship("VendorVersion", foreign_keys=[base_version_id])
    requester = relationship("User", foreign_keys=[requester_id])
    challenges = relationship("VerificationChallenge", back_populates="case")

    def __repr__(self) -> str:
        return f"<PayeeChangeCase {self.id} (State: {self.state})>"


class VerificationChallenge(Base):
    """
    Out-of-band verification challenge dispatched strictly to the pre-existing
    trusted contact email. Stores ONLY token hashes, never plaintext tokens.
    """
    __tablename__ = "verification_challenges"

    id = Column(String(36), primary_key=True)
    case_id = Column(String(36), ForeignKey("payee_change_cases.id", ondelete="RESTRICT"), nullable=False, index=True)
    vendor_id = Column(String(36), ForeignKey("vendors.id"), nullable=False)
    bound_base_version_id = Column(String(36), ForeignKey("vendor_versions.id"), nullable=False)
    bound_proposed_recipient = Column(String(255), nullable=False)
    bound_candidate_digest = Column(String(64), nullable=False)
    token_hash = Column(String(64), nullable=False, index=True)  # SHA-256 of token
    delivery_channel = Column(String(50), default="TRUSTED_EMAIL", nullable=False)
    delivery_destination = Column(String(255), nullable=False)  # Must match vendor.trusted_contact_email
    attempts = Column(Integer, default=0, nullable=False)
    max_attempts = Column(Integer, default=3, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    rejected_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    case = relationship("PayeeChangeCase", back_populates="challenges")

    def __repr__(self) -> str:
        return f"<VerificationChallenge {self.id} for Case {self.case_id}>"


class Approval(Base):
    """
    Exact transaction-bound or change-case approval.
    Binds vendor version, recipient, amount, currency, and expiration.
    Enforces distinct requester and approver.
    """
    __tablename__ = "approvals"

    id = Column(String(36), primary_key=True)
    approval_type = Column(String(50), nullable=False)  # CHANGE_CASE, PAYMENT_INTENT
    case_id = Column(String(36), ForeignKey("payee_change_cases.id"), nullable=True)
    payment_intent_id = Column(
        String(36),
        ForeignKey("payment_intents.id", use_alter=True, name="fk_approval_payment_intent"),
        nullable=True,
    )
    requester_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    approver_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    decision = Column(String(50), nullable=False)  # APPROVED, REJECTED
    bound_vendor_version_id = Column(String(36), ForeignKey("vendor_versions.id"), nullable=False)
    bound_recipient = Column(String(255), nullable=False)
    bound_amount_minor = Column(Integer, nullable=True)  # None for change cases
    bound_currency = Column(String(3), nullable=True)
    digest = Column(String(64), nullable=False)  # Cryptographic digest of approval parameters
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    invalidated_at = Column(DateTime(timezone=True), nullable=True)
    invalidation_reason = Column(String(255), nullable=True)

    requester = relationship("User", foreign_keys=[requester_id])
    approver = relationship("User", foreign_keys=[approver_id])
    bound_vendor_version = relationship("VendorVersion", foreign_keys=[bound_vendor_version_id])

    def __repr__(self) -> str:
        return f"<Approval {self.id} ({self.approval_type} -> {self.decision})>"


class PaymentIntent(Base):
    """
    Payment intention with exact amount in integer minor units (e.g. cents).
    Must be approved before submission.
    """
    __tablename__ = "payment_intents"

    id = Column(String(36), primary_key=True)
    vendor_id = Column(String(36), ForeignKey("vendors.id"), nullable=False, index=True)
    vendor_version_id = Column(String(36), ForeignKey("vendor_versions.id"), nullable=False)
    invoice_reference = Column(String(100), nullable=False)
    amount_minor = Column(Integer, nullable=False)  # Minor units (e.g. 100 = $1.00)
    currency = Column(String(3), default="USD", nullable=False)
    requester_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    state = Column(
        String(50),
        default="AWAITING_APPROVAL",
        nullable=False,
        index=True,
    )  # DRAFT, AWAITING_APPROVAL, APPROVED, INVALIDATED, SUBMISSION_RESERVED, SUBMITTED, SETTLED, FAILED, RECONCILE_REQUIRED
    approval_id = Column(String(36), ForeignKey("approvals.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    vendor = relationship("Vendor")
    vendor_version = relationship("VendorVersion")
    requester = relationship("User", foreign_keys=[requester_id])
    approval = relationship("Approval", foreign_keys=[approval_id], post_update=True)
    payout_attempts = relationship("PayoutAttempt", back_populates="payment_intent")

    def __repr__(self) -> str:
        return f"<PaymentIntent {self.id} (Amt: {self.amount_minor} {self.currency}, State: {self.state})>"


class PayoutAttempt(Base):
    """
    Records a payment submission attempt.
    The resolved recipient is determined strictly from the immutable VendorVersion,
    NEVER accepted from the caller or invoice.
    """
    __tablename__ = "payout_attempts"

    id = Column(String(36), primary_key=True)
    payment_intent_id = Column(String(36), ForeignKey("payment_intents.id"), nullable=False, index=True)
    sender_batch_id = Column(String(100), unique=True, nullable=False, index=True)
    sender_item_id = Column(String(100), unique=True, nullable=False, index=True)
    payout_batch_id = Column(String(100), nullable=True)
    payout_item_id = Column(String(100), nullable=True)
    state = Column(
        String(50),
        default="RESERVED",
        nullable=False,
        index=True,
    )  # RESERVED, SUBMITTED, SUCCESS, PENDING, UNCLAIMED, FAILED, RETURNED, RECONCILE_REQUIRED
    amount_minor = Column(Integer, nullable=False)
    currency = Column(String(3), nullable=False)
    resolved_recipient = Column(String(255), nullable=False)  # Sourced strictly from vendor_versions
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_provider_check = Column(DateTime(timezone=True), nullable=True)
    provider_response_redacted = Column(Text, nullable=True)

    payment_intent = relationship("PaymentIntent", back_populates="payout_attempts")

    def __repr__(self) -> str:
        return f"<PayoutAttempt {self.id} ({self.sender_batch_id} -> {self.state})>"


class AuditEvent(Base):
    """
    Append-only audit trail.
    All security-sensitive operations and state transitions are recorded.
    """
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True)
    event_type = Column(String(100), nullable=False, index=True)
    actor_id = Column(String(36), nullable=True, index=True)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(String(36), nullable=False, index=True)
    state_before = Column(String(50), nullable=True)
    state_after = Column(String(50), nullable=True)
    evidence_digest = Column(String(64), nullable=False)
    details_json = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<AuditEvent {self.event_type} on {self.entity_type}:{self.entity_id}>"
