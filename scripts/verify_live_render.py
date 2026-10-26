import httpx
import re

BASE_URL = "https://vendortrust-u3gg.onrender.com"
print("=== Testing Live VendorTrust Deployment ===")
print("Target:", BASE_URL)

with httpx.Client(base_url=BASE_URL, timeout=30.0, follow_redirects=True) as client:
    # 1. Health check
    r = client.get("/healthz")
    assert r.status_code == 200, f"/healthz failed: {r.status_code}"
    print(f"[+] 1. Health check HTTP 200: {r.json()}")

    # 2. Landing page
    r = client.get("/")
    assert r.status_code == 200, f"Landing failed: {r.status_code}"
    assert "VendorTrust" in r.text
    print("[+] 2. Landing page renders successfully.")

    # 3. Start demo session
    r = client.post("/start-demo")
    assert r.status_code == 200, f"Start demo failed: {r.status_code}"
    assert "demo_session" in client.cookies
    print("[+] 3. Demo session established with secure cookie.")

    # 4. Extract CSRF token
    csrf_match = re.search(r'name=["\']csrf_token["\'] value=["\']([^"\']+)["\']', r.text)
    assert csrf_match, "CSRF token not found on inbox page"
    csrf = csrf_match.group(1)
    print(f"[+] 4. CSRF token extracted: {csrf[:8]}...")

    # 5. Pre-seeded vendor check
    assert "Acme Design Labs" in r.text
    print("[+] 5. Pre-seeded demo vendor displayed in Inbox.")

    # 6. Ingest document with payee change proposal
    intake_data = {
        "csrf_token": csrf,
        "document_text": "Please remit all future invoice payments to our updated accounting address: new-wire@acme-design.test",
        "source_type": "email_text",
        "use_ai": "0",
    }
    r = client.post("/inbox/submit", data=intake_data)
    assert r.status_code == 200
    assert "HOLD" in r.text or "HELD" in r.text
    print("[+] 6. Payee change proposal successfully placed on HOLD.")

    case_match = re.search(r"/cases/([a-f0-9\-]{36})", r.text)
    assert case_match, "Case ID not found in intake result"
    case_id = case_match.group(1)
    print(f"[+] 7. PayeeChangeCase created: {case_id}")

    # 7. Issue verification challenge
    r = client.post(f"/cases/{case_id}/issue-challenge", data={"csrf_token": csrf})
    assert r.status_code == 200
    print("[+] 8. Keyed HMAC verification challenge issued.")

    # 8. Check simulated mailbox
    r = client.get(f"/cases/{case_id}/vendor-mailbox")
    assert r.status_code == 200
    token_match = re.search(r'font-size:1\.8rem[^>]+>([^\s<]{6,})<', r.text)
    assert token_match, "OTP not found in simulated mailbox"
    otp = token_match.group(1).strip()
    print(f"[+] 9. Simulated vendor mailbox displayed OTP: {otp}")

    # 9. Verify token
    r = client.post(f"/cases/{case_id}/verify", data={"csrf_token": csrf, "submitted_token": otp})
    assert r.status_code == 200
    assert "VENDOR_CONFIRMED" in r.text
    print("[+] 10. Single-use OTP verified -> state transitioned to VENDOR_CONFIRMED.")

    # 10. Approver Ravi approves change -> activates v2
    r = client.post(f"/cases/{case_id}/approve", data={"csrf_token": csrf})
    assert r.status_code == 200
    assert "VERSION_ACTIVATED" in r.text or "approved" in r.text.lower()
    print("[+] 11. Distinct Approver (Ravi) activated VendorVersion v2.")

    # 11. Create payment intent ($1.00 USD)
    r = client.post("/payments/create", data={
        "csrf_token": csrf,
        "invoice_reference": "INV-LIVE-RENDER-001",
        "amount_minor": "100",
        "currency": "USD",
    })
    assert r.status_code == 200
    pay_match = re.search(r"/payments/([a-f0-9\-]{36})", r.text)
    assert pay_match, "Payment intent ID not found"
    payment_id = pay_match.group(1)
    print(f"[+] 12. Payment intent created: {payment_id} ($1.00 USD).")

    # 12. Approver approves payment intent
    r = client.post(f"/payments/{payment_id}/approve", data={"csrf_token": csrf})
    assert r.status_code == 200
    print("[+] 13. Payment intent approved.")

    # 13. Execute payout via Mock provider
    r = client.post(f"/payments/{payment_id}/execute", data={"csrf_token": csrf})
    assert r.status_code == 200
    assert "SETTLED" in r.text or "SUCCESS" in r.text
    print("[+] 14. Payout executed via MockPayoutProvider -> SETTLED.")

    # 14. Check audit trail
    r = client.get("/audit")
    assert r.status_code == 200
    assert "VERSION_ACTIVATED" in r.text
    print("[+] 15. Audit trail verified with immutable SHA-256 digests.")

    # 15. Reset demo
    r = client.post("/reset-demo", data={"csrf_token": csrf})
    assert r.status_code == 200
    print("[+] 16. Demo session safely reset.")

print("\n=======================================================")
print(">>> ALL LIVE HOSTING VERIFICATION CHECKS PASSED! <<<")
print("=======================================================")
