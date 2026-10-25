# PayPal Gate 2 Evidence Log

> **Defensible Claim:** VendorTrust executed a genuine PayPal sandbox payout ($1.00 USD) governed by deterministic recipient-versioning and multi-party approval controls, with simulated human verification and identity channels.

## Status

**Current Result:** PASS (Item-Level SUCCESS Confirmed)

---

## Scope & Simulation Boundaries

To maintain rigorous transparency for the hackathon evaluation, the boundaries between real and simulated controls are explicitly stated below:

| System Component | Execution Reality | Boundary & Implementation Details |
|---|---|---|
| **PayPal Sandbox Payout** | **GENUINE** | Dispatched via `PayPalSandboxPayoutAdapter` to `https://api-m.sandbox.paypal.com`. Recorded item-level `SUCCESS`. |
| **Recipient Resolution** | **GENUINE** | Payout recipient resolved strictly from immutable database record `VendorVersion.paypal_recipient`. Caller-supplied recipient override blocked. |
| **Pre-Commit Idempotency** | **GENUINE** | Stable `sender_batch_id` persisted in SQLite in `RESERVED` status prior to outbound network dispatch. |
| **Two-Person Separation** | **SIMULATED IDENTITIES** | Asha (Requester) and Ravi (Approver) are seeded demonstration personas enforcing database-level role separation; not authenticated via external enterprise SSO. |
| **Vendor Verification** | **SIMULATED CONFIRMATION** | Verification challenge generated and verified locally in simulation using a keyed single-use HMAC token. No external email was dispatched over SMTP. |
| **AI Intake Analysis** | **LIVE INFERENCE (SMOKE TEST)** | Evaluated live against Google Gemini (`gemini-3-flash-preview`) with honest provider attribution. |

---

## Protocol Verification Summary

1. **Two-Person Separation Enforced:** Asha (Requester persona) submitted the change proposal; Ravi (Approver persona) authorized version activation and approved the payment intent. Self-approval was blocked by business logic.
2. **Deterministic Hold Enforced:** Untrusted document proposal immediately placed the vendor in a `HELD` state with a `PayeeChangeCase`.
3. **Simulated Vendor Confirmation:** A keyed HMAC single-use verification challenge was generated in simulation and verified locally against its SHA-256 hash.
4. **Immutable Versioning Activated:** Vendor version v1 (`bootstrap-old@acme-design.test`) remained immutably archived; version v2 (`sb-ztl4c53532381@personal.example.com`) was created and activated append-only. Triggers prevented direct SQL updates or deletions.
5. **Strict Recipient Binding:** PaymentIntent was cryptographically bound to approved Version v2. Outbound payout resolved the destination address exclusively from v2.
6. **Pre-commit Idempotency & Settle:** Unique `sender_batch_id` pre-committed in `RESERVED` state before PayPal API transmission. Network response was polled until PayPal returned item-level `SUCCESS`.

---

## Genuine PayPal Sandbox Evidence Record

| Field | Verified Value |
|---|---|
| **Tested at (UTC)** | 2026-10-25 13:40:14 UTC |
| **Sandbox API Base URL** | `https://api-m.sandbox.paypal.com` |
| **Execution Mode** | `PRIVATE_SANDBOX` |
| **Operator Authentication** | Authenticated (`OPERATOR_API_KEY` >= 32 characters validated) |
| **Recipient Account** | `s***@personal.example.com` (Legitimate Personal Sandbox) |
| **Amount & Currency** | $1.00 USD (`100` minor units) |
| **Stable Sender Batch ID** | `vt_batch_b5d2d5c0a093` |
| **PayPal Payout Batch ID** | `BFLWZHMJWV9MC` |
| **PayPal Payout Item ID** | `ZHUA56M7XGLUL` |
| **Initial Payout Status** | `PENDING` / `PROCESSING` |
| **Final Payout Attempt State** | `SUCCESS` |
| **Final Payment Intent State** | `SETTLED` |
| **Item-Level SUCCESS Confirmed** | **YES** |

---

## Live Gemini AI Evaluation (Smoke Test)

Live inference was validated against the upstream Gemini API using model `gemini-3-flash-preview`:

| Test Message | System Result | Attribution & Safety Interpretation |
|---|---|---|
| **1. Standard Invoice with Bank Details** | `UNCERTAIN` (Human Hold) | **Safe Fail-Closed:** The model flagged banking coordinate text as ambiguous rather than declaring the payee cleanly unchanged. This correctly resulted in a conservative hold rather than an automated pass-through. |
| **2. Explicit Payee Change Request** | Candidate Extracted | Successfully identified candidate recipient `new-billing@acmewidgets.com`; deterministically created `PayeeChangeCase` in `HELD` state. |
| **3. Prompt Injection Override Attempt** | Security Hold | System detected adversarial prompt override tokens; refused to loosen deterministic policy and enforced manual review. |
| **4. Ambiguous Invoice Text** | `MANUAL_EXTRACTION_REVIEW` | Missing clear recipient patterns resulted in a manual review case with `proposed_recipient=NULL`. |

*Note:* This 4-message evaluation serves as an illustrative integration smoke test demonstrating live model connectivity and fail-closed security properties, not a statistically comprehensive accuracy benchmark.
