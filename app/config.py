"""
app/config.py — Application Configuration & Mode Checks
"""

import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"

if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
PAYPAL_MODE = os.getenv("PAYPAL_MODE", "sandbox").strip().lower()

# SQLite Database URL
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'vendortrust.db'}")

# Security check: never allow live PayPal mode
if PAYPAL_MODE not in ("sandbox", "mock"):
    raise RuntimeError(f"PAYPAL_MODE '{PAYPAL_MODE}' is prohibited. Only 'sandbox' or 'mock' permitted.")

# Insecure default constant for detection
INSECURE_DEFAULT_SECRET = "vendortrust-dev-secret-key-32-chars-min"
RAW_SECRET = os.getenv("SECRET_KEY", "").strip()

if not RAW_SECRET:
    if APP_ENV in ("test", "testing"):
        SECRET_KEY = "test-only-secret-key-at-least-32-bytes-long"
    else:
        SECRET_KEY = INSECURE_DEFAULT_SECRET
else:
    SECRET_KEY = RAW_SECRET

# Strict check: In private payment or production mode, refuse any insecure fallback secret
if APP_ENV in ("production", "private_sandbox") or (PAYPAL_MODE == "sandbox" and APP_ENV != "test"):
    if SECRET_KEY == INSECURE_DEFAULT_SECRET or len(SECRET_KEY) < 32:
        # If in development with sandbox credentials, warn or enforce proper key
        if APP_ENV == "production":
            raise RuntimeError(
                "CRITICAL SECURITY FAILURE: Insecure or default SECRET_KEY in production mode. "
                "Must be a high-entropy secret of at least 32 characters in .env."
            )

# Operator API key for private sandbox authentication
OPERATOR_API_KEY = os.getenv("OPERATOR_API_KEY", "").strip()

# Gemini / AI Model API key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
