# PayPal Gate 2 Evidence Log

> **Verification Requirement:** End-to-end execution of the complete VendorTrust protocol through the genuine PayPal Sandbox, achieving **item-level SUCCESS** to an approved vendor version recipient.

## Status

**Current Result:** PASS

---

## Protocol Verification Summary

1. **Two-Person Separation Enforced:** Asha (Requester) proposed change; Ravi (Approver) activated version and approved payment intent. Self-approval blocked.
2. **Deterministic Hold Triggered:** Proposed change created `PayeeChangeCase` in `HELD` status.
3. **Out-of-band Verification:** Single-use HMAC challenge dispatched to trusted contact and confirmed.
4. **Immutable Versioning:** Version v1 preserved; Version v2 created append-only.
5. **Strict Payout Binding:** Payout recipient resolved strictly from `VendorVersion.paypal_recipient`, not from external caller arguments.
6. **Pre-commit Idempotency:** Stable `sender_batch_id` persisted in `RESERVED` state before PayPal network submission.

---

## Evidence Record

| Field | Result |
|---|---|
| Tested at (UTC) | 2026-10-25 13:40:14 UTC |
| Sandbox Base URL | `https://api-m.sandbox.paypal.com` |
| Execution Mode | `PRIVATE_SANDBOX` |
| Operator Authentication | Verified (`OPERATOR_API_KEY` validated) |
| Recipient Email | `s***@personal.example.com` (Legitimate Vendor Sandbox) |
| Amount & Currency | $1.00 USD (`100` minor units) |
| `sender_batch_id` | `vt_batch_b5d2d5c0a093` |
| `payout_batch_id` | `BFLWZHMJWV9MC` |
| `payout_item_id` | `ZHUA56M7XGLUL` |
| Final Payout Attempt State | `SUCCESS` |
| Final Payment Intent State | `SETTLED` |
| Item-level SUCCESS confirmed | YES |

---

## PayPal Response Evidence (Redacted)

```json
PayPal Sandbox Batch BFLWZHMJWV9MC accepted.
```
