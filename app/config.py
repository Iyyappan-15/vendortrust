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

SECRET_KEY = os.getenv("SECRET_KEY", "vendortrust-dev-secret-key-32-chars-min")
