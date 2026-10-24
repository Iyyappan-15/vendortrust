# PayPal Gate 1 Evidence Log

> **Verification Requirement:** Payouts sandbox capability must achieve **item-level SUCCESS** to a legitimate sandbox vendor account before core application or database code is written.

## Status

**Current Result:** PASS

---

## Evidence Record

| Field | Result |
|---|---|
| Tested at (UTC) | 2026-10-24 08:14:10 UTC |
| Sandbox payer account country/eligibility | US Sandbox Business |
| OAuth Token Exchange | SUCCESS |
| Payouts permission | GRANTED (Verified $1.00 USD Payout) |
| `sender_batch_id` | `vt_gate1_a7c0f610b265` |
| `payout_batch_id` | `LXPUQG4EAY4DU` |
| `payout_item_id` | `Q7NK8QVW4K7UJ` |
| Batch status | `PROCESSING` |
| Item status | `SUCCESS` |
| Item-level SUCCESS confirmed | YES |
| PayPal Debug ID | `f2023051e9d02` |
| Redacted failure/debug reference | Payout reached item-level SUCCESS. Sandbox account is fully eligible. |

---

## Execution Notes

- Payout Amount: $1.00 USD
- Target Recipient: Legitimate Vendor Sandbox Account
- Endpoint Base: `https://api-m.sandbox.paypal.com`
- Verification Rule: Payout is considered passed ONLY if `item status == SUCCESS`. Batch-level acknowledgment alone is insufficient.
