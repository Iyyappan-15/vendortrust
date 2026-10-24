#!/usr/bin/env python3
"""
scripts/test_paypal_gate1.py — PayPal Sandbox Payouts Gate 1 Verification Script

Purpose:
  Operator-only verification of PayPal Sandbox OAuth and outbound Payouts eligibility.
  Submits exactly ONE $1.00 USD sandbox payout to the legitimate vendor test account,
  polls for batch completion, inspects the individual payout item status, and writes
  redacted evidence to docs/GATE1_EVIDENCE.md.

Security Constraints:
  - Exclusively targets https://api-m.sandbox.paypal.com
  - Credentials loaded from local .env; never logged or committed
  - Gate 1 payout target MUST be PAYPAL_VENDOR_EMAIL, NEVER PAYPAL_ATTACKER_EMAIL
  - Persists batch identifier before network submission to prevent duplicate payouts
  - Supports automated reconciliation of existing batches
  - Marks Gate 1 PASS only on item-level SUCCESS
"""

import argparse
import datetime
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import httpx
from dotenv import load_dotenv

# Define strict paths
ROOT_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT_DIR / ".env"
STATE_FILE = ROOT_DIR / ".gate1_state.json"
EVIDENCE_FILE = ROOT_DIR / "docs" / "GATE1_EVIDENCE.md"

SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"
PAYOUT_AMOUNT = "1.00"
PAYOUT_CURRENCY = "USD"


def mask_email(email: str) -> str:
    """Mask email for safe console and evidence logging."""
    if not email or "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def load_and_validate_env() -> Dict[str, str]:
    """Load and validate necessary environment variables."""
    if not ENV_FILE.exists():
        print(f"[ERROR] Environment file not found at {ENV_FILE}")
        print("Please copy .env.example to .env and fill in your PayPal Sandbox credentials.")
        sys.exit(1)

    load_dotenv(dotenv_path=ENV_FILE)

    mode = os.getenv("PAYPAL_MODE", "sandbox").strip().lower()
    if mode != "sandbox":
        print(f"[ERROR] PAYPAL_MODE is '{mode}'. Gate 1 refuses to run in any mode other than 'sandbox'!")
        sys.exit(1)

    client_id = os.getenv("PAYPAL_CLIENT_ID", "").strip()
    client_secret = os.getenv("PAYPAL_CLIENT_SECRET", "").strip()
    vendor_email = os.getenv("PAYPAL_VENDOR_EMAIL", "").strip()
    attacker_email = os.getenv("PAYPAL_ATTACKER_EMAIL", "").strip()

    if not client_id or not client_secret:
        print("[ERROR] Missing PAYPAL_CLIENT_ID or PAYPAL_CLIENT_SECRET in .env.")
        sys.exit(1)

    if not vendor_email:
        print("[ERROR] Missing PAYPAL_VENDOR_EMAIL in .env. Specify a legitimate sandbox personal account.")
        sys.exit(1)

    # Security check: Never send Gate 1 money to the attacker account
    if attacker_email and vendor_email.lower() == attacker_email.lower():
        print("[FATAL SECURITY VIOLATION] PAYPAL_VENDOR_EMAIL equals PAYPAL_ATTACKER_EMAIL!")
        print("Gate 1 payout must ONLY be sent to the legitimate vendor sandbox account.")
        sys.exit(1)

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "vendor_email": vendor_email,
        "attacker_email": attacker_email,
    }


def load_state() -> Optional[Dict[str, Any]]:
    """Load persistent Gate 1 execution state if present."""
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[WARN] Could not parse {STATE_FILE}: {e}")
    return None


def save_state(state: Dict[str, Any]) -> None:
    """Save persistent Gate 1 execution state."""
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def get_oauth_token(client: httpx.Client, client_id: str, client_secret: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Request OAuth 2.0 access token via client credentials grant.
    Returns (access_token, debug_id).
    """
    token_url = f"{SANDBOX_BASE_URL}/v1/oauth2/token"
    headers = {
        "Accept": "application/json",
        "Accept-Language": "en_US",
    }
    data = {"grant_type": "client_credentials"}

    print("[*] Requesting OAuth 2.0 access token from PayPal Sandbox...")
    try:
        response = client.post(
            token_url,
            headers=headers,
            data=data,
            auth=(client_id, client_secret),
            timeout=20.0,
        )
    except httpx.RequestError as e:
        print(f"[ERROR] Network error during OAuth token exchange: {e}")
        return None, None

    debug_id = response.headers.get("paypal-debug-id") or response.headers.get("PayPal-Debug-Id")

    if response.status_code != 200:
        print(f"[ERROR] OAuth authentication failed with HTTP {response.status_code}")
        print(f"Debug ID: {debug_id}")
        try:
            err_json = response.json()
            print(f"Error Name: {err_json.get('error', 'UNKNOWN')}")
            print(f"Description: {err_json.get('error_description', 'No description provided')}")
        except Exception:
            print(f"Response: {response.text[:200]}")
        return None, debug_id

    try:
        token_data = response.json()
        token = token_data.get("access_token")
        print("[+] OAuth authentication successful.")
        return token, debug_id
    except Exception as e:
        print(f"[ERROR] Failed to parse OAuth response: {e}")
        return None, debug_id


def submit_payout(
    client: httpx.Client,
    access_token: str,
    sender_batch_id: str,
    sender_item_id: str,
    vendor_email: str,
) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[Dict[str, Any]]]:
    """
    Submit a $1.00 USD payout batch with a single item to the vendor.
    Returns (success, payout_batch_id, batch_status, debug_id, error_details).
    """
    payout_url = f"{SANDBOX_BASE_URL}/v1/payments/payouts"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
    }

    payload = {
        "sender_batch_header": {
            "sender_batch_id": sender_batch_id,
            "email_subject": "VendorTrust Sandbox Gate 1 Verification",
            "email_message": "You received a $1.00 USD verification payment from VendorTrust.",
        },
        "items": [
            {
                "recipient_type": "EMAIL",
                "amount": {
                    "value": PAYOUT_AMOUNT,
                    "currency": PAYOUT_CURRENCY,
                },
                "receiver": vendor_email,
                "note": "VendorTrust Gate 1 Verification Payment",
                "sender_item_id": sender_item_id,
            }
        ],
    }

    print(f"[*] Submitting payout to PayPal Sandbox...")
    print(f"    Recipient: {mask_email(vendor_email)}")
    print(f"    Amount: ${PAYOUT_AMOUNT} {PAYOUT_CURRENCY}")
    print(f"    Sender Batch ID: {sender_batch_id}")

    try:
        response = client.post(payout_url, headers=headers, json=payload, timeout=25.0)
    except httpx.RequestError as e:
        print(f"[ERROR] Network error during payout submission: {e}")
        return False, None, None, None, {"name": "NETWORK_TIMEOUT", "message": str(e)}

    debug_id = response.headers.get("paypal-debug-id") or response.headers.get("PayPal-Debug-Id")

    if response.status_code not in (200, 201):
        print(f"[ERROR] Payout submission failed with HTTP {response.status_code}")
        print(f"Debug ID: {debug_id}")
        error_details = {}
        try:
            error_details = response.json()
            err_name = error_details.get("name", "UNKNOWN_ERROR")
            err_msg = error_details.get("message", "No message")
            print(f"PayPal Error: {err_name} - {err_msg}")
            if "details" in error_details:
                print(f"Details: {json.dumps(error_details['details'], indent=2)}")
        except Exception:
            print(f"Raw response: {response.text[:300]}")
            error_details = {"raw": response.text[:300]}
        return False, None, None, debug_id, error_details

    try:
        res_data = response.json()
        batch_header = res_data.get("batch_header", {})
        payout_batch_id = batch_header.get("payout_batch_id")
        batch_status = batch_header.get("batch_status")
        print(f"[+] Payout batch accepted by PayPal.")
        print(f"    Payout Batch ID: {payout_batch_id}")
        print(f"    Batch Status: {batch_status}")
        return True, payout_batch_id, batch_status, debug_id, None
    except Exception as e:
        print(f"[ERROR] Failed to parse payout submission response: {e}")
        return False, None, None, debug_id, {"name": "PARSE_ERROR", "message": str(e)}


def fetch_payout_batch(
    client: httpx.Client, access_token: str, payout_batch_id: str
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Retrieve payout batch details.
    Returns (batch_status, first_payout_item_id, first_item_status, debug_id).
    """
    url = f"{SANDBOX_BASE_URL}/v1/payments/payouts/{payout_batch_id}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
    }

    try:
        response = client.get(url, headers=headers, timeout=20.0)
    except httpx.RequestError as e:
        print(f"[WARN] Error fetching batch status: {e}")
        return None, None, None, None

    debug_id = response.headers.get("paypal-debug-id") or response.headers.get("PayPal-Debug-Id")

    if response.status_code != 200:
        print(f"[WARN] Failed to fetch batch details (HTTP {response.status_code}), Debug ID: {debug_id}")
        return None, None, None, debug_id

    try:
        data = response.json()
        batch_header = data.get("batch_header", {})
        batch_status = batch_header.get("batch_status")
        items = data.get("items", [])
        item_id = None
        item_status = None
        if items:
            item_id = items[0].get("payout_item_id")
            item_status = items[0].get("transaction_status")
        return batch_status, item_id, item_status, debug_id
    except Exception as e:
        print(f"[WARN] Failed to parse batch details: {e}")
        return None, None, None, debug_id


def fetch_payout_item(
    client: httpx.Client, access_token: str, payout_item_id: str
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Retrieve individual payout item status.
    Returns (transaction_status, time_processed, debug_id).
    """
    url = f"{SANDBOX_BASE_URL}/v1/payments/payouts-item/{payout_item_id}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
    }

    try:
        response = client.get(url, headers=headers, timeout=20.0)
    except httpx.RequestError as e:
        print(f"[WARN] Error fetching item status: {e}")
        return None, None, None

    debug_id = response.headers.get("paypal-debug-id") or response.headers.get("PayPal-Debug-Id")

    if response.status_code != 200:
        print(f"[WARN] Failed to fetch item details (HTTP {response.status_code}), Debug ID: {debug_id}")
        return None, None, debug_id

    try:
        data = response.json()
        tx_status = data.get("transaction_status")
        time_processed = data.get("time_processed")
        return tx_status, time_processed, debug_id
    except Exception as e:
        print(f"[WARN] Failed to parse item details: {e}")
        return None, None, debug_id


def poll_for_completion(
    client: httpx.Client,
    access_token: str,
    payout_batch_id: str,
    max_wait_seconds: int = 40,
    poll_interval: int = 3,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Poll PayPal Sandbox until payout batch and item reach a terminal state or timeout.
    Returns (final_batch_status, payout_item_id, final_item_status).
    """
    print(f"[*] Polling status for Payout Batch {payout_batch_id} (up to {max_wait_seconds}s)...")
    start_time = time.time()
    last_batch_status = None
    item_id = None
    last_item_status = None

    while time.time() - start_time < max_wait_seconds:
        batch_status, b_item_id, b_item_status, _ = fetch_payout_batch(client, access_token, payout_batch_id)
        if batch_status:
            last_batch_status = batch_status
        if b_item_id:
            item_id = b_item_id
        if b_item_status:
            last_item_status = b_item_status

        # If we have an item ID, check the item directly
        if item_id:
            direct_item_status, _, _ = fetch_payout_item(client, access_token, item_id)
            if direct_item_status:
                last_item_status = direct_item_status

        print(f"    -> Batch: {last_batch_status or 'UNKNOWN'} | Item: {last_item_status or 'PENDING'}")

        # Check terminal conditions
        if last_item_status in ("SUCCESS", "FAILED", "BLOCKED", "REFUNDED", "RETURNED", "UNCLAIMED"):
            break

        time.sleep(poll_interval)

    return last_batch_status, item_id, last_item_status


def write_evidence(
    result_status: str,
    tested_at_utc: str,
    payer_country: str,
    oauth_status: str,
    payouts_permission: str,
    sender_batch_id: str,
    payout_batch_id: str,
    payout_item_id: str,
    batch_status: str,
    item_status: str,
    success_confirmed: str,
    debug_id: str,
    details: str,
) -> None:
    """Generate or update docs/GATE1_EVIDENCE.md with redacted evidence."""
    EVIDENCE_FILE.parent.mkdir(parents=True, exist_ok=True)

    content = f"""# PayPal Gate 1 Evidence Log

> **Verification Requirement:** Payouts sandbox capability must achieve **item-level SUCCESS** to a legitimate sandbox vendor account before core application or database code is written.

## Status

**Current Result:** {result_status}

---

## Evidence Record

| Field | Result |
|---|---|
| Tested at (UTC) | {tested_at_utc} |
| Sandbox payer account country/eligibility | {payer_country} |
| OAuth Token Exchange | {oauth_status} |
| Payouts permission | {payouts_permission} |
| `sender_batch_id` | `{sender_batch_id}` |
| `payout_batch_id` | `{payout_batch_id}` |
| `payout_item_id` | `{payout_item_id}` |
| Batch status | `{batch_status}` |
| Item status | `{item_status}` |
| Item-level SUCCESS confirmed | {success_confirmed} |
| PayPal Debug ID | `{debug_id}` |
| Redacted failure/debug reference | {details} |

---

## Execution Notes

- Payout Amount: $1.00 USD
- Target Recipient: Legitimate Vendor Sandbox Account
- Endpoint Base: `https://api-m.sandbox.paypal.com`
- Verification Rule: Payout is considered passed ONLY if `item status == SUCCESS`. Batch-level acknowledgment alone is insufficient.
"""
    with open(EVIDENCE_FILE, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"[+] Updated evidence log: {EVIDENCE_FILE}")


def main():
    parser = argparse.ArgumentParser(description="VendorTrust PayPal Gate 1 Verification Script")
    parser.add_argument("--reconcile", action="store_true", help="Reconcile existing pending batch from state file")
    parser.add_argument("--force-new", action="store_true", help="Force a new batch submission even if state exists")
    args = parser.parse_args()

    print("=" * 70)
    print(" VendorTrust — PayPal Gate 1 Sandbox Verification")
    print("=" * 70)

    env_config = load_and_validate_env()
    client_id = env_config["client_id"]
    client_secret = env_config["client_secret"]
    vendor_email = env_config["vendor_email"]

    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    state = load_state()

    with httpx.Client() as client:
        # Step 1: OAuth Authentication
        access_token, oauth_debug_id = get_oauth_token(client, client_id, client_secret)
        if not access_token:
            print("\n[-] GATE 1 FAILED AT OAUTH AUTHENTICATION.")
            write_evidence(
                result_status="BLOCKED (OAuth Failed)",
                tested_at_utc=now_utc,
                payer_country="US Sandbox Business",
                oauth_status="FAILED",
                payouts_permission="NOT TESTED",
                sender_batch_id="—",
                payout_batch_id="—",
                payout_item_id="—",
                batch_status="—",
                item_status="—",
                success_confirmed="NO",
                debug_id=oauth_debug_id or "—",
                details="OAuth client credentials invalid or unauthorized.",
            )
            sys.exit(1)

        # Step 2: Check for existing un-reconciled batch or recovery
        should_reconcile = args.reconcile
        if state and state.get("payout_batch_id") and not args.force_new:
            if state.get("last_item_status") == "SUCCESS":
                print(f"[i] State file shows existing successful run for batch {state.get('payout_batch_id')}.")
                print("    Use --force-new to run another verification test.")
                should_reconcile = True
            elif not should_reconcile:
                print(f"[i] Found existing batch {state.get('payout_batch_id')} in state file.")
                print("    Defaulting to reconciliation mode to prevent duplicate submission.")
                should_reconcile = True

        if should_reconcile and state and state.get("payout_batch_id"):
            sender_batch_id = state.get("sender_batch_id", "—")
            payout_batch_id = state["payout_batch_id"]
            payout_item_id = state.get("payout_item_id")
            print(f"[*] Reconciling existing payout batch: {payout_batch_id}")

            batch_status, item_id, item_status = poll_for_completion(client, access_token, payout_batch_id)
            if item_id:
                payout_item_id = item_id

            state["last_batch_status"] = batch_status
            state["last_item_status"] = item_status
            state["payout_item_id"] = payout_item_id
            save_state(state)

            if item_status == "SUCCESS":
                print("\n[+] GATE 1 PASSED: Item-level SUCCESS confirmed on reconciliation!")
                write_evidence(
                    result_status="PASS (Reconciled)",
                    tested_at_utc=now_utc,
                    payer_country="US Sandbox Business",
                    oauth_status="SUCCESS",
                    payouts_permission="GRANTED",
                    sender_batch_id=sender_batch_id,
                    payout_batch_id=payout_batch_id,
                    payout_item_id=payout_item_id or "—",
                    batch_status=batch_status or "SUCCESS",
                    item_status="SUCCESS",
                    success_confirmed="YES",
                    debug_id="—",
                    details="Verified item-level SUCCESS via reconciliation.",
                )
                sys.exit(0)
            else:
                print(f"\n[-] GATE 1 INCOMPLETE: Item status is '{item_status}'.")
                write_evidence(
                    result_status=f"UNRESOLVED ({item_status})",
                    tested_at_utc=now_utc,
                    payer_country="US Sandbox Business",
                    oauth_status="SUCCESS",
                    payouts_permission="CHECK_REQUIRED",
                    sender_batch_id=sender_batch_id,
                    payout_batch_id=payout_batch_id,
                    payout_item_id=payout_item_id or "—",
                    batch_status=batch_status or "—",
                    item_status=item_status or "—",
                    success_confirmed="NO",
                    debug_id="—",
                    details=f"Item has not reached SUCCESS. Status: {item_status}",
                )
                sys.exit(1)

        # Step 3: Submission / Idempotent Recovery
        # If a previous submission attempt occurred with a sender_batch_id but payout_batch_id was missing (e.g. timeout),
        # reuse the exact same sender_batch_id and sender_item_id to uphold idempotency.
        if state and state.get("sender_batch_id") and not state.get("payout_batch_id") and not args.force_new:
            print(f"[i] Recovering previously generated batch ID {state['sender_batch_id']} to preserve idempotency...")
            sender_batch_id = state["sender_batch_id"]
            sender_item_id = state.get("sender_item_id", f"item_{uuid.uuid4().hex[:8]}")
        else:
            sender_batch_id = f"vt_gate1_{uuid.uuid4().hex[:12]}"
            sender_item_id = f"item_{uuid.uuid4().hex[:8]}"

        # Persist intent BEFORE network submission
        state = {
            "sender_batch_id": sender_batch_id,
            "sender_item_id": sender_item_id,
            "vendor_email_masked": mask_email(vendor_email),
            "amount": PAYOUT_AMOUNT,
            "currency": PAYOUT_CURRENCY,
            "created_at_utc": now_utc,
            "submitted": False,
            "payout_batch_id": None,
            "payout_item_id": None,
            "last_batch_status": None,
            "last_item_status": None,
        }
        save_state(state)

        # Execute submission
        success, payout_batch_id, batch_status, p_debug_id, error_details = submit_payout(
            client=client,
            access_token=access_token,
            sender_batch_id=sender_batch_id,
            sender_item_id=sender_item_id,
            vendor_email=vendor_email,
        )

        state["submitted"] = True
        state["payout_batch_id"] = payout_batch_id
        state["last_batch_status"] = batch_status
        save_state(state)

        if not success:
            print("\n[-] GATE 1 BLOCKED / REJECTED DURING PAYOUT SUBMISSION.")
            err_name = error_details.get("name", "PAYOUT_ERROR") if error_details else "PAYOUT_ERROR"
            err_msg = error_details.get("message", "Request failed") if error_details else "Request failed"
            write_evidence(
                result_status=f"BLOCKED ({err_name})",
                tested_at_utc=now_utc,
                payer_country="US Sandbox Business",
                oauth_status="SUCCESS",
                payouts_permission="DENIED / NOT ELIGIBLE",
                sender_batch_id=sender_batch_id,
                payout_batch_id="—",
                payout_item_id="—",
                batch_status="FAILED",
                item_status="FAILED",
                success_confirmed="NO",
                debug_id=p_debug_id or "—",
                details=f"{err_name}: {err_msg}",
            )
            sys.exit(1)

        # Step 4: Poll batch and item status
        final_batch_status, payout_item_id, final_item_status = poll_for_completion(
            client=client,
            access_token=access_token,
            payout_batch_id=payout_batch_id,
        )

        state["payout_item_id"] = payout_item_id
        state["last_batch_status"] = final_batch_status
        state["last_item_status"] = final_item_status
        save_state(state)

        # Step 5: Evaluate Gate 1 criteria
        print("\n" + "=" * 70)
        print(" Gate 1 Evaluation Result")
        print("=" * 70)
        print(f"Payout Batch ID : {payout_batch_id}")
        print(f"Payout Item ID  : {payout_item_id or 'NOT RETURNED'}")
        print(f"Batch Status    : {final_batch_status}")
        print(f"Item Status     : {final_item_status}")

        if final_item_status == "SUCCESS":
            print("\n>>> [PASS] Gate 1 PASSED: Item reached SUCCESS in PayPal Sandbox.")
            write_evidence(
                result_status="PASS",
                tested_at_utc=now_utc,
                payer_country="US Sandbox Business",
                oauth_status="SUCCESS",
                payouts_permission="GRANTED (Verified $1.00 USD Payout)",
                sender_batch_id=sender_batch_id,
                payout_batch_id=payout_batch_id,
                payout_item_id=payout_item_id or "—",
                batch_status=final_batch_status or "SUCCESS",
                item_status="SUCCESS",
                success_confirmed="YES",
                debug_id=p_debug_id or "—",
                details="Payout reached item-level SUCCESS. Sandbox account is fully eligible.",
            )
            sys.exit(0)
        else:
            print(f"\n>>> [-] Gate 1 DID NOT PASS: Item status is '{final_item_status}'.")
            write_evidence(
                result_status=f"UNRESOLVED ({final_item_status})",
                tested_at_utc=now_utc,
                payer_country="US Sandbox Business",
                oauth_status="SUCCESS",
                payouts_permission="UNCERTAIN",
                sender_batch_id=sender_batch_id,
                payout_batch_id=payout_batch_id,
                payout_item_id=payout_item_id or "—",
                batch_status=final_batch_status or "—",
                item_status=final_item_status or "UNKNOWN",
                success_confirmed="NO",
                debug_id=p_debug_id or "—",
                details=f"Item reached '{final_item_status}' instead of 'SUCCESS'. Run with --reconcile if pending.",
            )
            sys.exit(1)


if __name__ == "__main__":
    main()
