# VendorTrust — Safe Public Deployment Guide

> **Core Deployment Invariant:** The public deployment runs **exclusively** in `PUBLIC_DEMO` mode using `MockPayoutProvider`. No PayPal credentials, operator secrets, or private execution endpoints exist on the public host.

---

## 1. Architecture & Security Invariants

| Security Control | Public Deployment Configuration | Verification |
|---|---|---|
| **Execution Mode** | `PUBLIC_DEMO` | Session isolation via per-visitor in-memory SQLite (`sqlite://`). |
| **Payout Provider** | `MockPayoutProvider` | All web UI payouts are simulated with full UI lifecycle; zero outbound PayPal API calls. |
| **PayPal Credentials** | **NONE** (`PAYPAL_CLIENT_ID` and `PAYPAL_CLIENT_SECRET` omitted) | Application starts and runs cleanly with mock provider. |
| **Operator Secret** | **NONE** (`OPERATOR_API_KEY` omitted) | Private sandbox execution endpoints are inaccessible without operator authentication. |
| **Worker Concurrency** | **Single Worker (`--workers 1`)** | In-memory demo sessions remain coherent across requests without external cache or shared state fragmentation. |
| **Session Protection** | **Secure Cookies + CSRF** | Cookies set with `HttpOnly=True`, `SameSite=Lax`, and `Secure=True` under HTTPS. Per-session CSRF tokens validated on all POST routes. |
| **Health Checks** | `/health` & `/healthz` | Returns HTTP 200 with service metadata and operational status. |

---

## 2. Environment Variables for Public Deployment

Configure only these environment variables on your public host (e.g., Render, Railway, Fly.io, Cloud Run):

```bash
# Application Environment
APP_ENV=production
PAYPAL_MODE=mock

# High-entropy Session Key (generate locally: python -c "import secrets; print(secrets.token_urlsafe(32))")
SECRET_KEY=<32-character-random-hex-or-urlsafe-secret>

# Optional: Google Gemini API key for live AI extraction in the public demo.
# If omitted, VendorTrust automatically falls back to deterministic heuristic parsing labeled [HEURISTIC].
GEMINI_API_KEY=<optional-gemini-key>
GEMINI_MODEL=gemini-3-flash-preview

# Security Cookies
SECURE_COOKIES=true

# Container Port (automatically provided by Render/Railway/Cloud Run, default 8000)
PORT=8000
```

> [!CAUTION]
> **DO NOT SET** `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, or `OPERATOR_API_KEY` in the public deployment environment.

---

## 3. Deployment Artifacts

The repository includes ready-to-deploy configurations:

### A. Procfile (Render / Railway / Heroku)
```
web: uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1
```

### B. Dockerfile (Container / Cloud Run)
```dockerfile
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 APP_ENV=production PAYPAL_MODE=mock PORT=8000
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -u 1000 -m appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
```

---

## 4. Verification & Fresh-Browser Walkthrough Checklist

Before sharing the public link:
1. **Health Check:**
   ```bash
   curl -i https://<your-deployed-app>/healthz
   # Expected: HTTP 200 {"status":"healthy","service":"vendortrust","mode":"PUBLIC_DEMO","paypal_mode":"mock","version":"1.0.0"}
   ```
2. **Fresh Browser Test:**
   - Open an incognito / private browser window.
   - Navigate to `/` -> click **Start Live Demo**.
   - Confirm redirect to `/inbox` with isolated demo session cookie.
   - Submit a test document proposing a new payee email -> verify **HOLD (HELD)** status is triggered.
   - Open **Simulated Vendor Mailbox** -> verify single-use OTP.
   - Confirm verification challenge -> approve version activation -> observe Version v2 activated.
   - Create payment intent -> approve payment -> click **Execute Payout** -> observe **SETTLED (Mock Provider)** status.
   - Review `/audit` timeline -> verify all transitions are recorded with SHA-256 cryptographic digests.
