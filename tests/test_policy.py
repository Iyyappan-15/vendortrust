"""
tests/test_policy.py — Tests for Pure Deterministic Policy Rules
"""

from app.services.policy import (
    PolicyDecision,
    evaluate_payee_change_proposal,
    validate_minor_units_amount,
)


def test_evaluate_payee_change_matching():
    """Matching payee allows standard review."""
    decision, reason = evaluate_payee_change_proposal(
        active_recipient="vendor@example.test",
        candidate_recipient="vendor@example.test",
    )
    assert decision == PolicyDecision.ALLOW_REVIEW
    assert reason == "PAYEE_MATCHES_ACTIVE_VERSION"


def test_evaluate_payee_change_mismatch():
    """Mismatch in payee triggers mandatory HOLD."""
    decision, reason = evaluate_payee_change_proposal(
        active_recipient="vendor@example.test",
        candidate_recipient="attacker-changed@example.test",
    )
    assert decision == PolicyDecision.HOLD
    assert reason == "PAYEE_MISMATCH_DETECTED"


def test_evaluate_payee_change_none_extracted():
    """Missing or unextracted candidate defaults to standard review."""
    decision, reason = evaluate_payee_change_proposal(
        active_recipient="vendor@example.test",
        candidate_recipient=None,
    )
    assert decision == PolicyDecision.ALLOW_REVIEW
    assert reason == "PAYEE_UNCHANGED"


def test_minor_units_amount_validation():
    """Amount must be positive integer minor units."""
    assert validate_minor_units_amount(100) is True
    assert validate_minor_units_amount(1) is True
    assert validate_minor_units_amount(0) is False
    assert validate_minor_units_amount(-50) is False
    assert validate_minor_units_amount(12.50) is False  # type: ignore
