"""
app/services/policy.py — Pure Deterministic Policy Functions
"""

from typing import Optional, Tuple


class PolicyDecision:
    ALLOW_REVIEW = "ALLOW_REVIEW"
    HOLD = "HOLD"
    REJECT = "REJECT"


def evaluate_payee_change_proposal(
    active_recipient: str,
    candidate_recipient: Optional[str],
) -> Tuple[str, str]:
    """
    Pure decision function comparing active payee vs candidate extracted payee.
    Returns (decision, reason_code).
    """
    if not candidate_recipient:
        # No new recipient proposed -> proceed with standard payment review
        return PolicyDecision.ALLOW_REVIEW, "PAYEE_UNCHANGED"

    clean_active = active_recipient.strip().lower()
    clean_candidate = candidate_recipient.strip().lower()

    if clean_candidate == clean_active:
        return PolicyDecision.ALLOW_REVIEW, "PAYEE_MATCHES_ACTIVE_VERSION"

    # Mismatch detected -> MUST HOLD
    return PolicyDecision.HOLD, "PAYEE_MISMATCH_DETECTED"


def validate_minor_units_amount(amount_minor: int) -> bool:
    """Validate that amount is positive integer minor units (no floating point calculations)."""
    return isinstance(amount_minor, int) and amount_minor > 0
