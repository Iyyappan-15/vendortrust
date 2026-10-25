"""
app/services/payout_adapter.py — PayPal Sandbox Payouts Adapter & Mode Isolation

Strict Security Constraints:
- Sandbox URL only: https://api-m.sandbox.paypal.com
- Hard-rejects any live PayPal base URL or non-sandbox mode.
- Requires server-enforced operator authentication to execute real sandbox calls.
- Public demo execution is completely isolated and uses MockPayoutProvider only.
- Payout parameters are resolved strictly from the approved PaymentIntent and immutable VendorVersion.
"""

import os
from typing import Any, Dict, Optional
import httpx

from app.config import OPERATOR_API_KEY, PAYPAL_MODE
from app.services.exceptions import SecurityViolationError

SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"


class ExecutionMode:
    PUBLIC_DEMO = "PUBLIC_DEMO"
    PRIVATE_SANDBOX = "PRIVATE_SANDBOX"


class PayPalSandboxPayoutAdapter:
    """
    Operator-authenticated PayPal Sandbox Payouts Adapter.
    Communicates with https://api-m.sandbox.paypal.com using server-side credentials.
    """
    def __init__(self, client_id: str, client_secret: str):
        if PAYPAL_MODE != "sandbox":
            raise SecurityViolationError(f"Prohibited PAYPAL_MODE '{PAYPAL_MODE}'. Adapter only functions in sandbox mode.")

        if not client_id or not client_secret:
            raise SecurityViolationError("Missing PayPal Sandbox client ID or client secret.")

        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = SANDBOX_BASE_URL

    def _get_access_token(self) -> str:
        """Fetch OAuth 2.0 access token via client credentials grant."""
        url = f"{self.base_url}/v1/oauth2/token"
        headers = {
            "Accept": "application/json",
            "Accept-Language": "en_US",
        }
        data = {"grant_type": "client_credentials"}

        with httpx.Client(timeout=20.0) as client:
            resp = client.post(url, headers=headers, data=data, auth=(self.client_id, self.client_secret))
            if resp.status_code != 200:
                raise RuntimeError(f"PayPal Sandbox OAuth failed (HTTP {resp.status_code}): {resp.text[:200]}")
            return resp.json()["access_token"]

    def execute_payout(
        self,
        sender_batch_id: str,
        sender_item_id: str,
        recipient_email: str,
        amount_minor: int,
        currency: str,
    ) -> Dict[str, Any]:
        """
        Submits payout to PayPal Sandbox API.
        Formats amount from integer minor units (e.g. 100 -> "1.00").
        """
        access_token = self._get_access_token()
        url = f"{self.base_url}/v1/payments/payouts"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
        }

        # Convert integer cents to exact decimal string
        amount_decimal = f"{amount_minor / 100:.2f}"

        payload = {
            "sender_batch_header": {
                "sender_batch_id": sender_batch_id,
                "email_subject": "VendorTrust Verified Payout",
                "email_message": f"You received a payout of {amount_decimal} {currency} from VendorTrust.",
            },
            "items": [
                {
                    "recipient_type": "EMAIL",
                    "amount": {
                        "value": amount_decimal,
                        "currency": currency,
                    },
                    "receiver": recipient_email,
                    "note": "Verified vendor payment by VendorTrust protocol",
                    "sender_item_id": sender_item_id,
                }
            ],
        }

        with httpx.Client(timeout=25.0) as client:
            try:
                resp = client.post(url, headers=headers, json=payload)
            except httpx.RequestError as e:
                return {
                    "success": False,
                    "uncertain": True,
                    "payout_batch_id": None,
                    "payout_item_id": None,
                    "batch_status": "TIMEOUT",
                    "item_status": "RECONCILE_REQUIRED",
                    "response_redacted": f"Network exception during PayPal dispatch: {str(e)}",
                }

            if resp.status_code not in (200, 201):
                err_text = resp.text[:300]
                return {
                    "success": False,
                    "uncertain": False,
                    "payout_batch_id": None,
                    "payout_item_id": None,
                    "batch_status": "FAILED",
                    "item_status": "FAILED",
                    "response_redacted": f"PayPal API Error HTTP {resp.status_code}: {err_text}",
                }

            data = resp.json()
            batch_header = data.get("batch_header", {})
            payout_batch_id = batch_header.get("payout_batch_id")
            batch_status = batch_header.get("batch_status")

            # Follow-up: Poll batch to retrieve first item ID
            first_item_id = None
            first_item_status = "PENDING"
            if payout_batch_id:
                batch_info = self.get_batch_status(payout_batch_id, access_token=access_token)
                first_item_id = batch_info.get("first_item_id")
                first_item_status = batch_info.get("first_item_status", "PENDING")

            return {
                "success": first_item_status == "SUCCESS",
                "uncertain": first_item_status in ("PENDING", "PROCESSING", "UNCLAIMED"),
                "payout_batch_id": payout_batch_id,
                "payout_item_id": first_item_id,
                "batch_status": batch_status,
                "item_status": first_item_status,
                "response_redacted": f"PayPal Sandbox Batch {payout_batch_id} accepted.",
            }

    def get_batch_status(self, payout_batch_id: str, access_token: Optional[str] = None) -> Dict[str, Any]:
        """Query PayPal Sandbox for payout batch details."""
        token = access_token or self._get_access_token()
        url = f"{self.base_url}/v1/payments/payouts/{payout_batch_id}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }

        with httpx.Client(timeout=20.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                return {"batch_status": "UNKNOWN", "first_item_id": None, "first_item_status": "UNKNOWN"}

            data = resp.json()
            batch_status = data.get("batch_header", {}).get("batch_status")
            items = data.get("items", [])
            first_id = None
            first_status = None
            if items:
                first_id = items[0].get("payout_item_id")
                first_status = items[0].get("transaction_status")

            return {
                "batch_status": batch_status,
                "first_item_id": first_id,
                "first_item_status": first_status or "PENDING",
            }

    def get_item_status(self, payout_item_id: str) -> Dict[str, Any]:
        """Query PayPal Sandbox for individual item status."""
        token = self._get_access_token()
        url = f"{self.base_url}/v1/payments/payouts-item/{payout_item_id}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }

        with httpx.Client(timeout=20.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                return {"transaction_status": "UNKNOWN", "time_processed": None}

            data = resp.json()
            return {
                "transaction_status": data.get("transaction_status", "UNKNOWN"),
                "time_processed": data.get("time_processed"),
            }


def resolve_payout_provider(
    execution_mode: str,
    operator_token: Optional[str] = None,
    mock_desired_status: str = "SUCCESS",
):
    """
    Enforces mode separation between PUBLIC_DEMO and PRIVATE_SANDBOX.
    - PUBLIC_DEMO: Strictly returns MockPayoutProvider. Real credentials cannot be loaded.
    - PRIVATE_SANDBOX: Requires server-enforced operator authorization token.
    """
    if execution_mode == ExecutionMode.PUBLIC_DEMO:
        # Public visitors always get mock provider
        from app.services.payouts import MockPayoutProvider
        return MockPayoutProvider(desired_item_status=mock_desired_status)

    if execution_mode == ExecutionMode.PRIVATE_SANDBOX:
        # Server-enforced operator authorization
        if not operator_token or (OPERATOR_API_KEY and operator_token != OPERATOR_API_KEY):
            raise SecurityViolationError("Unauthorized access to Private Sandbox Payout Execution. Valid operator credentials required.")

        client_id = os.getenv("PAYPAL_CLIENT_ID", "").strip()
        client_secret = os.getenv("PAYPAL_CLIENT_SECRET", "").strip()

        if not client_id or not client_secret:
            raise SecurityViolationError("PayPal Sandbox credentials not configured in server environment.")

        return PayPalSandboxPayoutAdapter(client_id=client_id, client_secret=client_secret)

    raise ValueError(f"Unknown execution mode '{execution_mode}'.")
