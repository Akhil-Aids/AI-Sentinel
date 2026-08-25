"""Central configuration for AI Sentinel.

All runtime settings come from environment variables (with safe defaults for
local development). No secrets are hard-coded. Loaded once at import time.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Workspace root is the directory that contains the `backend/` and `frontend/`
# folders. `.env` lives there.
WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
ENV_PATH = WORKSPACE_ROOT / ".env"
load_dotenv(dotenv_path=ENV_PATH)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


class Settings:
    APP_NAME = "AI Sentinel"
    APP_VERSION = "2.0.0"
    ENV = os.getenv("SENTINEL_ENV", "development")
    DEBUG = _env_bool("SENTINEL_DEBUG", False)

    # Deployment environment of the monitored asset (production|staging|development).
    ENVIRONMENT = os.getenv("SENTINEL_ENVIRONMENT", "development")

    # --- Secrets / auth -----------------------------------------------------
    # A strong random value MUST be provided in production.
    AUTH_SECRET = os.getenv("SENTINEL_AUTH_SECRET") or "development-only-change-me"
    TOKEN_TTL_SECONDS = _env_int("SENTINEL_TOKEN_TTL", 8 * 60 * 60)
    ADMIN_PASSWORD = os.getenv("SENTINEL_ADMIN_PASSWORD", "")

    # --- Agent API key (for endpoint agents pushing telemetry) --------------
    AGENT_KEY = os.getenv("SENTINEL_AGENT_KEY", "")

    # --- Network trust --------------------------------------------------------
    # Comma-separated proxy IPs whose X-Forwarded-For header is trusted for
    # client-IP derivation and rate limiting. Empty = ignore the header (direct).
    TRUSTED_PROXIES = [p.strip() for p in os.getenv("SENTINEL_TRUSTED_PROXIES", "").split(",") if p.strip()]

    # --- Storage -------------------------------------------------------------
    DB_PATH = Path(os.getenv("SENTINEL_DB_PATH") or str(WORKSPACE_ROOT / "data" / "sentinel.db"))
    RETENTION_DAYS = _env_int("SENTINEL_RETENTION_DAYS", 30)

    # --- Pipeline ------------------------------------------------------------
    WORKER_CONSUMERS = _env_int("SENTINEL_WORKERS", 2)
    QUEUE_MAXSIZE = _env_int("SENTINEL_QUEUE_MAXSIZE", 20000)

    # --- Event lifecycle latency targets (ms) --------------------------------
    # End-to-end targets: event -> dashboard. critical rules get a tighter target.
    LATENCY_TARGET_EVENT_MS = _env_int("SENTINEL_LATENCY_TARGET_EVENT_MS", 2000)
    LATENCY_TARGET_CRITICAL_MS = _env_int("SENTINEL_LATENCY_TARGET_CRITICAL_MS", 5000)

    # --- Telemetry ------------------------------------------------------------
    METRICS_INTERVAL = _env_int("SENTINEL_METRICS_INTERVAL", 15)
    FILE_INTERVAL = _env_int("SENTINEL_FILE_INTERVAL", 30)

    # --- Agent heartbeat ------------------------------------------------------
    # Seconds without a heartbeat => DEGRADED, then OFFLINE.
    AGENT_DEGRADED_SECONDS = _env_int("SENTINEL_AGENT_DEGRADED_SECONDS", 45)
    AGENT_OFFLINE_SECONDS = _env_int("SENTINEL_AGENT_OFFLINE_SECONDS", 120)

    # --- ML ------------------------------------------------------------------
    MODEL_DIR = Path(os.getenv("SENTINEL_MODEL_DIR") or str(WORKSPACE_ROOT / "backend" / "models"))
    ML_RETRAIN_MIN_SAMPLES = _env_int("SENTINEL_ML_RETRAIN_MIN_SAMPLES", 200)
    ML_CONTAMINATION = float(os.getenv("SENTINEL_ML_CONTAMINATION", "0.05"))
    ML_ENABLED = _env_bool("SENTINEL_ML_ENABLED", True)

    # --- Phishing ------------------------------------------------------------
    PHISHING_ENABLED = _env_bool("SENTINEL_PHISHING_ENABLED", True)

    # --- Threat intelligence --------------------------------------------------
    TI_ENABLED = _env_bool("SENTINEL_TI_ENABLED", False)
    TI_VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    TI_ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

    # --- Response engine ------------------------------------------------------
    # When true, response engine only records intended actions without executing.
    RESPONSE_DRY_RUN = _env_bool("SENTINEL_RESPONSE_DRY_RUN", True)

    # --- Frontend -------------------------------------------------------------
    CORS_ORIGINS = [o.strip() for o in os.getenv("SENTINEL_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()]

    # --- Directory monitored for file-change events ----------------------------
    MONITOR_DIRS = [p.strip() for p in os.getenv("SENTINEL_MONITOR_DIRS", str(WORKSPACE_ROOT / "backend")).split(";") if p.strip()]

    # --- Simulated / demo mode -------------------------------------------------
    # Explicitly off unless enabled. Demo mode never feeds the production store.
    # --- Backup protection ----------------------------------------------------
    BACKUP_TARGETS = [p.strip() for p in os.getenv("SENTINEL_BACKUP_TARGETS", "").split(";") if p.strip()]

    # --- Simulated / demo mode -------------------------------------------------
    # Explicitly off unless enabled. Demo mode never feeds the production store.
    DEMO_MODE = _env_bool("SENTINEL_DEMO_MODE", False)


settings = Settings()


def validate_settings() -> None:
    """Fail fast on unsafe configurations. Called once at startup."""
    dev_secret = "development-only-change-me"
    if settings.ENV == "production" and settings.AUTH_SECRET == dev_secret:
        raise RuntimeError(
            "SENTINEL_ENV=production requires a real SENTINEL_AUTH_SECRET. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )
    if settings.ENV == "production" and settings.ENVIRONMENT == "development":
        raise RuntimeError(
            "SENTINEL_ENV=production requires SENTINEL_ENVIRONMENT to be set to "
            "'production', 'staging' or 'development' (the environment of the monitored assets)."
        )
    if settings.ENV == "production" and settings.ADMIN_PASSWORD:
        raise RuntimeError(
            "SENTINEL_ENV=production must not set SENTINEL_ADMIN_PASSWORD (use the "
            "generated bootstrap password and rotate it after first login)."
        )
