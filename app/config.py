import os
from dotenv import load_dotenv

load_dotenv()

WEAK_SECRETS = {"", "change-me", "changeme", "secret", "password"}
WEAK_ADMIN_PASSWORDS = {"admin@123", "password1234", "changeme1234", "administrator"}


def check_secret(key: str) -> str:
    """Refuse to start with a guessable token-signing key (anyone could forge logins)."""
    if len(key) < 32 or key.lower() in WEAK_SECRETS or "change-me" in key.lower():
        raise RuntimeError(
            "SECRET_KEY must be at least 32 random characters. Make one with: "
            "python -c \"import secrets; print(secrets.token_urlsafe(48))\"")
    return key


def check_admin_password(password: str) -> str:
    if len(password) < 12 or password.lower() in WEAK_ADMIN_PASSWORDS:
        raise SystemExit("ADMIN_PASSWORD must be at least 12 characters and not a common one")
    return password


DATABASE_URL = os.environ["DATABASE_URL"]
if DATABASE_URL.startswith("postgres://"):          # Render/Heroku style
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
SECRET_KEY = check_secret(os.environ["SECRET_KEY"])
TOKEN_MINUTES = 60
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "uploads")
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_REQUEST_BYTES = MAX_UPLOAD_BYTES + 1024 * 1024   # file plus multipart overhead

# /docs and /openapi.json only when explicitly switched on (your own machine)
ENABLE_DOCS = os.environ.get("ENABLE_DOCS", "0") == "1"

# throttling, counted from the audit log (survives restarts, no extra service)
THROTTLE_WINDOW_MINUTES = 15
LOGIN_MAX_PER_EMAIL_AND_IP = 5     # same account, same address
LOGIN_MAX_PER_IP = 30              # one address trying many accounts
LOGIN_MAX_PER_EMAIL = 30           # one account attacked from many addresses
REGISTER_MAX_PER_IP_PER_HOUR = 20

# Optional Telegram real-time alerts
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_BOT_USERNAME = os.environ.get("TELEGRAM_BOT_USERNAME", "").strip()

# Optional SMTP Email Alerts
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
try:
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
except ValueError:
    SMTP_PORT = 587
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").strip()
SMTP_FROM = os.environ.get("SMTP_FROM", "").strip() or SMTP_USER or "no-reply@trustvault.local"

# Optional Google Gemini AI Service
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()

