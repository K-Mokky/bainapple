"""Application configuration.

All security-sensitive values are sourced from environment variables so that
no secret is ever committed to the repository. Safe, clearly-marked defaults
are provided only for local development.
"""
import os
import secrets


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


class Config:
    # --- Secrets ---------------------------------------------------------
    # SECRET_KEY MUST be provided in production. For local dev we fall back to
    # an ephemeral random key (sessions reset on restart) and warn loudly.
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SECRET_KEY_IS_EPHEMERAL = SECRET_KEY is None
    if SECRET_KEY is None:
        SECRET_KEY = secrets.token_hex(32)

    # --- Database --------------------------------------------------------
    DATABASE = os.environ.get("DATABASE", "market.db")

    # --- Session / cookie hardening -------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Enable Secure cookies automatically when served over HTTPS (production).
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = _env_int("SESSION_LIFETIME_SECONDS", 3600)

    # --- CSRF ------------------------------------------------------------
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # tie CSRF token lifetime to the session

    # --- Uploads ---------------------------------------------------------
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "market/static/uploads")
    MAX_CONTENT_LENGTH = _env_int("MAX_UPLOAD_BYTES", 3 * 1024 * 1024)  # 3 MB
    ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

    # --- Business / moderation rules ------------------------------------
    REPORT_BLOCK_THRESHOLD = _env_int("REPORT_BLOCK_THRESHOLD", 3)

    # --- Auth throttling -------------------------------------------------
    LOGIN_MAX_ATTEMPTS = _env_int("LOGIN_MAX_ATTEMPTS", 5)
    LOGIN_LOCKOUT_SECONDS = _env_int("LOGIN_LOCKOUT_SECONDS", 300)

    # Registration throttling per client IP (limits mass account creation and
    # username-enumeration probing of the "already exists" response).
    REGISTER_MAX_ATTEMPTS = _env_int("REGISTER_MAX_ATTEMPTS", 10)
    REGISTER_WINDOW_SECONDS = _env_int("REGISTER_WINDOW_SECONDS", 300)

    # --- Chat throttling -------------------------------------------------
    CHAT_MAX_MESSAGES = _env_int("CHAT_MAX_MESSAGES", 10)
    CHAT_WINDOW_SECONDS = _env_int("CHAT_WINDOW_SECONDS", 10)
    CHAT_MAX_LENGTH = _env_int("CHAT_MAX_LENGTH", 500)

    # --- Seed admin (created on first init if absent) --------------------
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")  # None => not auto-seeded
    # Path of the admin key file. Only a client holding this exact key file
    # can pass the admin gate (require.txt §8). Generated on first run.
    ADMIN_KEY_FILE = os.environ.get("ADMIN_KEY_FILE", "instance/admin_key.txt")

    # --- Field limits ----------------------------------------------------
    USERNAME_MIN = 3
    USERNAME_MAX = 20
    PASSWORD_MIN = 8
    PASSWORD_MAX = 128
    BIO_MAX = 500
    PRODUCT_TITLE_MAX = 100
    PRODUCT_DESC_MAX = 2000
    PRODUCT_PRICE_MAX = 1_000_000_000
    REASON_MAX = 500
    SEARCH_MIN_LENGTH = 2
    BANK_NAME_MAX = 30
    ACCOUNT_NUMBER_MAX = 30
    ACCOUNT_HOLDER_MAX = 30

    # --- Product categories ----------------------------------------------
    # Fixed server-side whitelist: the browse filter and the product forms
    # only ever accept one of these values.
    PRODUCT_CATEGORIES = (
        "디지털기기",
        "생활가전",
        "가구/인테리어",
        "생활/주방",
        "의류/패션",
        "도서/티켓/취미",
        "스포츠/레저",
        "기타",
    )
    PRODUCT_CATEGORY_DEFAULT = "기타"
