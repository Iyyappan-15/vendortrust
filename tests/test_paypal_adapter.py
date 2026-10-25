"""
tests/test_paypal_adapter.py — PayPal Sandbox Payouts Adapter & Mode Isolation Tests

Covers:
1. Mode isolation: PUBLIC_DEMO strictly resolves to MockPayoutProvider.
2. Operator authorization: PRIVATE_SANDBOX requires valid operator token.
3. Sandbox-only enforcement: Rejects live or invalid PAYPAL_MODE.
4. HTTP request contract: OAuth token grant, payouts dispatch payload, decimal conversion.
5. Batch and item reconciliation.
6. Timeout / network failure recovery without creating duplicate payout instructions.
7. Strict API invariant: Payout recipient resolved strictly from immutable VendorVersion.
"""

import json
import pytest
import httpx
from unittest.mock import MagicMock, patch

from app.models import PaymentIntent, PayoutAttempt, VendorVersion
from app.services.exceptions import SecurityViolationError
from app.services.approvals import approve_payment_intent, create_payment_intent
from app.services.payout_adapter import (
    ExecutionMode,
    PayPalSandboxPayoutAdapter,
    SANDBOX_BASE_URL,
    resolve_payout_provider,
)
from app.services.payouts import (
    MockPayoutProvider,
    reconcile_payout_attempt,
    submit_approved_payout,
)


def test_public_demo_resolves_mock_provider():
    """Public demo mode strictly returns MockPayoutProvider, isolating real credentials."""
    provider = resolve_payout_provider(
        execution_mode=ExecutionMode.PUBLIC_DEMO,
        operator_token=None,
    )
    assert isinstance(provider, MockPayoutProvider)


def test_private_sandbox_requires_valid_operator_token(monkeypatch):
    """Private sandbox mode strictly rejects requests without valid operator token."""
    monkeypatch.setenv("OPERATOR_API_KEY", "super-secret-operator-key-xyz")
    # Reload config value
    import app.services.payout_adapter as adapter_module
    monkeypatch.setattr(adapter_module, "OPERATOR_API_KEY", "super-secret-operator-key-xyz")

    # Missing token
    with pytest.raises(SecurityViolationError, match="Unauthorized access"):
        resolve_payout_provider(
            execution_mode=ExecutionMode.PRIVATE_SANDBOX,
            operator_token=None,
        )

    # Invalid token
    with pytest.raises(SecurityViolationError, match="Unauthorized access"):
        resolve_payout_provider(
            execution_mode=ExecutionMode.PRIVATE_SANDBOX,
            operator_token="wrong-token-abc",
        )


def test_sandbox_only_mode_enforcement(monkeypatch):
    """Adapter refuses to initialize if PAYPAL_MODE is not 'sandbox'."""
    import app.services.payout_adapter as adapter_module
    monkeypatch.setattr(adapter_module, "PAYPAL_MODE", "live")

    with pytest.raises(SecurityViolationError, match="Adapter only functions in sandbox mode"):
        PayPalSandboxPayoutAdapter(client_id="dummy_id", client_secret="dummy_secret")


def test_sandbox_adapter_oauth_and_payout_dispatch():
    """Verify PayPal Sandbox HTTP contract: OAuth token retrieval and payout payload."""
    adapter = PayPalSandboxPayoutAdapter(client_id="test_client_id", client_secret="test_secret")

    oauth_response = {
        "access_token": "sandbox_oauth_token_12345",
        "token_type": "Bearer",
        "expires_in": 32400,
    }

    payout_post_response = {
        "batch_header": {
            "payout_batch_id": "PAYPAL_BATCH_999",
            "batch_status": "PENDING",
            "sender_batch_header": {
                "sender_batch_id": "sb_100",
            },
        }
    }

    batch_get_response = {
        "batch_header": {
            "payout_batch_id": "PAYPAL_BATCH_999",
            "batch_status": "SUCCESS",
        },
        "items": [
            {
                "payout_item_id": "PAYPAL_ITEM_888",
                "transaction_status": "SUCCESS",
            }
        ],
    }

    def mock_httpx_post(url, *args, **kwargs):
        if "/v1/oauth2/token" in url:
            assert kwargs.get("auth") == ("test_client_id", "test_secret")
            assert kwargs.get("data") == {"grant_type": "client_credentials"}
            return httpx.Response(200, json=oauth_response)
        elif "/v1/payments/payouts" in url:
            assert kwargs.get("headers", {}).get("Authorization") == "Bearer sandbox_oauth_token_12345"
            payload = kwargs.get("json", {})
            # Verify integer minor amount was converted to decimal string "1.50"
            assert payload["items"][0]["amount"]["value"] == "1.50"
            assert payload["items"][0]["amount"]["currency"] == "USD"
            assert payload["items"][0]["receiver"] == "vendor@acme.test"
            assert payload["sender_batch_header"]["sender_batch_id"] == "batch_unique_1"
            return httpx.Response(201, json=payout_post_response)
        raise ValueError(f"Unexpected POST url {url}")

    def mock_httpx_get(url, *args, **kwargs):
        if "/v1/payments/payouts/PAYPAL_BATCH_999" in url:
            assert kwargs.get("headers", {}).get("Authorization") == "Bearer sandbox_oauth_token_12345"
            return httpx.Response(200, json=batch_get_response)
        raise ValueError(f"Unexpected GET url {url}")

    with patch("httpx.Client.post", side_effect=mock_httpx_post), \
         patch("httpx.Client.get", side_effect=mock_httpx_get):
        result = adapter.execute_payout(
            sender_batch_id="batch_unique_1",
            sender_item_id="item_unique_1",
            recipient_email="vendor@acme.test",
            amount_minor=150,  # $1.50
            currency="USD",
        )

    assert result["success"] is True
    assert result["payout_batch_id"] == "PAYPAL_BATCH_999"
    assert result["payout_item_id"] == "PAYPAL_ITEM_888"
    assert result["item_status"] == "SUCCESS"


def test_sandbox_adapter_handles_network_timeout():
    """Network timeouts return uncertain=True, prompting reconciliation rather than duplicate payout."""
    adapter = PayPalSandboxPayoutAdapter(client_id="test_client_id", client_secret="test_secret")

    oauth_response = {"access_token": "sandbox_oauth_token_12345"}

    def mock_httpx_post(url, *args, **kwargs):
        if "/v1/oauth2/token" in url:
            return httpx.Response(200, json=oauth_response)
        elif "/v1/payments/payouts" in url:
            raise httpx.RequestError("Connection reset by peer")
        raise ValueError(f"Unexpected POST url {url}")

    with patch("httpx.Client.post", side_effect=mock_httpx_post):
        result = adapter.execute_payout(
            sender_batch_id="batch_timeout_1",
            sender_item_id="item_timeout_1",
            recipient_email="vendor@acme.test",
            amount_minor=100,
            currency="USD",
        )

    assert result["success"] is False
    assert result["uncertain"] is True
    assert result["item_status"] == "RECONCILE_REQUIRED"


def test_reconciliation_resolves_uncertain_payout(db_session, seeded_env):
    """
    When a payout is in an uncertain state, reconciliation queries PayPal item status
    and updates the existing attempt to SUCCESS without re-submitting money.
    """
    vendor = seeded_env["vendor"]
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    v1 = seeded_env["v1"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-TEST-RECONCILE",
        amount_minor=100,
        currency="USD",
        requester_id=asha.id,
    )
    approval = approve_payment_intent(
        session=db_session,
        payment_intent_id=intent.id,
        approver_id=ravi.id,
    )

    import uuid
    # Create an uncertain payout attempt
    attempt = PayoutAttempt(
        id=str(uuid.uuid4()),
        payment_intent_id=intent.id,
        sender_batch_id="batch_uncertain_1",
        sender_item_id="item_uncertain_1",
        payout_batch_id="PAYPAL_BATCH_RECONCILE",
        payout_item_id="PAYPAL_ITEM_RECONCILE",
        state="RESERVED",
        amount_minor=intent.amount_minor,
        currency=intent.currency,
        resolved_recipient=v1.paypal_recipient,
    )
    db_session.add(attempt)
    db_session.commit()

    # Mock provider returning item status SUCCESS
    mock_provider = MagicMock()
    mock_provider.get_item_status.return_value = {
        "transaction_status": "SUCCESS",
        "time_processed": "2026-10-25T10:00:00Z",
    }

    reconciled = reconcile_payout_attempt(
        session=db_session,
        payout_attempt_id=attempt.id,
        provider=mock_provider,
    )

    assert reconciled.state == "SUCCESS"
    assert intent.state == "SETTLED"
    mock_provider.get_item_status.assert_called_once_with("PAYPAL_ITEM_RECONCILE")


def test_strict_api_invariant_recipient_from_immutable_vendor_version(db_session, seeded_env):
    """
    Payment execution function accepts ONLY payment_intent_id.
    It resolves the payout recipient strictly from the immutable VendorVersion bound to the intent,
    never from external caller input.
    """
    vendor = seeded_env["vendor"]
    asha = seeded_env["asha"]
    ravi = seeded_env["ravi"]
    v1 = seeded_env["v1"]

    intent = create_payment_intent(
        session=db_session,
        vendor_id=vendor.id,
        invoice_reference="INV-TEST-INVARIANT",
        amount_minor=100,
        currency="USD",
        requester_id=asha.id,
    )
    approval = approve_payment_intent(
        session=db_session,
        payment_intent_id=intent.id,
        approver_id=ravi.id,
    )

    mock_provider = MockPayoutProvider(desired_item_status="SUCCESS")

    # Call strict execution: Note parameters are session, payment_intent_id, operator_actor_id, provider
    attempt = submit_approved_payout(
        session=db_session,
        payment_intent_id=intent.id,
        operator_actor_id=ravi.id,
        provider=mock_provider,
    )

    assert attempt.state == "SUCCESS"
    assert attempt.payment_intent_id == intent.id
    # Intent's immutable vendor version recipient is verified
    assert attempt.resolved_recipient == v1.paypal_recipient
    assert v1.paypal_recipient == "acme-pay@example.test"


def test_format_minor_amount_integer_precision():
    """Verify format_minor_amount formats exact USD minor units without float arithmetic."""
    from app.services.payout_adapter import format_minor_amount
    assert format_minor_amount(10000, "USD") == "100.00"
    assert format_minor_amount(100, "USD") == "1.00"
    assert format_minor_amount(1, "USD") == "0.01"
    assert format_minor_amount(550, "USD") == "5.50"
    assert format_minor_amount(105, "USD") == "1.05"

    with pytest.raises(ValueError, match="positive"):
        format_minor_amount(0, "USD")

    with pytest.raises(ValueError, match="positive"):
        format_minor_amount(-100, "USD")

    with pytest.raises(ValueError, match="Unsupported currency"):
        format_minor_amount(100, "EUR")


def test_operator_api_key_fail_closed_when_empty_or_too_short(monkeypatch):
    """
    If OPERATOR_API_KEY is not set, blank, or less than 16 chars,
    private sandbox mode must fail closed and reject all requests.
    """
    import app.services.payout_adapter as adapter_module

    # Case 1: Empty string
    monkeypatch.setattr(adapter_module, "OPERATOR_API_KEY", "")
    with pytest.raises(SecurityViolationError, match="not securely configured"):
        resolve_payout_provider(ExecutionMode.PRIVATE_SANDBOX, operator_token="any-token-here")

    # Case 2: Too short (< 16 chars)
    monkeypatch.setattr(adapter_module, "OPERATOR_API_KEY", "short-key-123")
    with pytest.raises(SecurityViolationError, match="not securely configured"):
        resolve_payout_provider(ExecutionMode.PRIVATE_SANDBOX, operator_token="short-key-123")

    # Case 3: Proper key, but attacker sends empty token
    monkeypatch.setattr(adapter_module, "OPERATOR_API_KEY", "a-sufficiently-long-secret-key-32b")
    with pytest.raises(SecurityViolationError, match="Unauthorized access"):
        resolve_payout_provider(ExecutionMode.PRIVATE_SANDBOX, operator_token="")
