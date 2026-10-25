"""
app/services/intake.py — Invoice/Email Intake Pipeline & Deterministic Case Creation

Binds untrusted text extraction to deterministic policy guards.
Guarantees that an invoice or AI proposal can NEVER authorize or directly execute a recipient change.
"""

from typing import Any, Dict, Optional, Tuple
from sqlalchemy.orm import Session
from app.models import PayeeChangeCase, Vendor, VendorVersion
from app.services.ai_extract import CandidateExtractionResult, extract_candidate_payee_change
from app.services.audit import record_audit_event
from app.services.challenges import create_payee_change_case
from app.services.policy import PolicyDecision, evaluate_payee_change_proposal
from app.services.vendor_registry import check_vendor_active, get_vendor


class IntakeProcessingResult:
    def __init__(
        self,
        decision: str,
        reason_code: str,
        case: Optional[PayeeChangeCase],
        candidate: CandidateExtractionResult,
        audit_event_id: Optional[str] = None,
    ):
        self.decision = decision
        self.reason_code = reason_code
        self.case = case
        self.candidate = candidate
        self.audit_event_id = audit_event_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "reason_code": self.reason_code,
            "case_id": self.case.id if self.case else None,
            "case_state": self.case.state if self.case else None,
            "candidate_recipient": self.candidate.proposed_recipient,
            "suspicious_instructions_present": self.candidate.suspicious_instructions_present,
            "evidence_snippet": self.candidate.evidence_snippet,
        }


def process_incoming_document(
    session: Session,
    vendor_id: str,
    untrusted_text: str,
    source_type: str,
    source_reference: str,
    requester_id: str,
    force_heuristic: bool = False,
) -> IntakeProcessingResult:
    """
    Core intake pipeline:
    1. Look up vendor and verified active version.
    2. Extract candidate payee change via AI extraction service (untrusted proposal).
    3. Run deterministic policy check comparing candidate recipient against verified active recipient.
    4. If mismatch detected: automatically creates a HELD PayeeChangeCase.
    5. Records append-only audit event.
    6. Invariant: Under no circumstances does this function modify vendor_versions or authorize payment.
    """
    vendor = get_vendor(session, vendor_id)
    check_vendor_active(vendor)

    active_version = session.query(VendorVersion).filter_by(id=vendor.active_version_id).first()
    if not active_version:
        raise ValueError(f"Vendor '{vendor_id}' has no verified active version.")

    # Step 1: AI candidate extraction (untrusted output)
    candidate = extract_candidate_payee_change(
        untrusted_text=untrusted_text,
        source_type=source_type,
        force_heuristic=force_heuristic,
    )

    # Step 2: Deterministic policy evaluation
    decision, reason = evaluate_payee_change_proposal(
        active_recipient=active_version.paypal_recipient,
        candidate_recipient=candidate.proposed_recipient if candidate.payee_change_requested else None,
    )

    # Step 3: Enforce hold if mismatch or suspicious prompt injection present
    case: Optional[PayeeChangeCase] = None

    if decision == PolicyDecision.HOLD or candidate.suspicious_instructions_present:
        target_proposed = candidate.proposed_recipient or "SUSPICIOUS_UNEXTRACTED_PAYEE"
        if target_proposed != active_version.paypal_recipient:
            case = create_payee_change_case(
                session=session,
                vendor_id=vendor.id,
                proposed_recipient=target_proposed,
                source_type=source_type,
                source_reference=source_reference,
                requester_id=requester_id,
            )
            decision = PolicyDecision.HOLD
            if candidate.suspicious_instructions_present:
                reason = "PAYEE_MISMATCH_WITH_SUSPICIOUS_INSTRUCTIONS"

    # Step 4: Audit logging
    audit = record_audit_event(
        session=session,
        event_type="INTAKE_DOCUMENT_PROCESSED",
        actor_id=requester_id,
        entity_type="VENDOR",
        entity_id=vendor.id,
        state_before=None,
        state_after=decision,
        details={
            "source_type": source_type,
            "source_reference": source_reference,
            "candidate_payee_change_requested": candidate.payee_change_requested,
            "candidate_proposed_recipient": candidate.proposed_recipient,
            "suspicious_instructions": candidate.suspicious_instructions_present,
            "decision": decision,
            "reason": reason,
            "case_id": case.id if case else None,
        },
    )
    session.commit()

    return IntakeProcessingResult(
        decision=decision,
        reason_code=reason,
        case=case,
        candidate=candidate,
        audit_event_id=audit.id,
    )
