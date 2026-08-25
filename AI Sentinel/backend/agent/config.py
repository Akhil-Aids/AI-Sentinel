"""Agent configuration.

All settings come from environment variables with sensible development
defaults.  `validate()` is called at startup and raises ValueError when
required production values are missing.
"""
import os
import platform
from dataclasses import dataclass, field


@dataclass(frozen=False)
class AgentConfig:
    SERVER_URL: str = ""
    AGENT_KEY: str = ""
    HOSTNAME: str = ""
    HEARTBEAT_INTERVAL: int = 30
    COLLECT_INTERVAL: int = 15
    RETRY_BASE_DELAY: float = 2.0
    RETRY_MAX_DELAY: float = 60.0
    BUFFER_MAX: int = 500
    FLUSH_BATCH_SIZE: int = 100
    PROTECTED_DIRS: list = field(default_factory=lambda: ["/etc", "/usr", "/var"])
    FILE_CHECK_INTERVAL: float = 5.0
    ENVIRONMENT: str = "development"

    @property
    def heartbeat_url(self) -> str:
        return f"{self.SERVER_URL.rstrip('/')}/api/agents/heartbeat"

    @property
    def ingest_url(self) -> str:
        return f"{self.SERVER_URL.rstrip('/')}/api/events/ingest/agent"

    def validate(self) -> None:
        if not self.SERVER_URL:
            raise ValueError("SENTINEL_AGENT_SERVER_URL is required")
        if not self.AGENT_KEY:
            raise ValueError("SENTINEL_AGENT_KEY is required")
        if self.HEARTBEAT_INTERVAL < 5:
            raise ValueError("Heartbeat interval must be >= 5 seconds")
        if self.COLLECT_INTERVAL < 5:
            raise ValueError("Collect interval must be >= 5 seconds")


def _env_int(key: str, default: int) -> int:
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return float(val)
    except ValueError:
        return default


def load_config() -> AgentConfig:
    hostname = os.getenv("SENTINEL_AGENT_HOSTNAME") or platform.node() or "unknown"
    protected = os.getenv("SENTINEL_AGENT_PROTECTED_DIRS", "/etc,/usr,/var")
    return AgentConfig(
        SERVER_URL=os.getenv("SENTINEL_AGENT_SERVER_URL", "http://localhost:8000"),
        AGENT_KEY=os.getenv("SENTINEL_AGENT_KEY", ""),
        HOSTNAME=hostname,
        HEARTBEAT_INTERVAL=_env_int("SENTINEL_AGENT_HEARTBEAT_INTERVAL", 30),
        COLLECT_INTERVAL=_env_int("SENTINEL_AGENT_COLLECT_INTERVAL", 15),
        RETRY_BASE_DELAY=_env_float("SENTINEL_AGENT_RETRY_BASE_DELAY", 2.0),
        RETRY_MAX_DELAY=_env_float("SENTINEL_AGENT_RETRY_MAX_DELAY", 60.0),
        BUFFER_MAX=_env_int("SENTINEL_AGENT_BUFFER_MAX", 500),
        FLUSH_BATCH_SIZE=_env_int("SENTINEL_AGENT_FLUSH_BATCH_SIZE", 100),
        PROTECTED_DIRS=[d.strip() for d in protected.split(",") if d.strip()],
        FILE_CHECK_INTERVAL=_env_float("SENTINEL_AGENT_FILE_CHECK_INTERVAL", 5.0),
        ENVIRONMENT=os.getenv("SENTINEL_ENVIRONMENT", "development"),
    )


config = load_config()
