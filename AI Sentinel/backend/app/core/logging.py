from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any


class JsonFormatter(logging.Formatter):
    """Emits each log record as a single compact JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "service": getattr(record, "service", "ai-sentinel"),
            "host": getattr(record, "host", _get_hostname()),
            "message": record.getMessage(),
        }

        request_id = getattr(record, "request_id", None)
        if request_id:
            log_entry["request_id"] = request_id

        event_id = getattr(record, "event_id", None)
        if event_id:
            log_entry["event_id"] = event_id

        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            log_entry.update(extra)

        return json.dumps(log_entry, ensure_ascii=False, separators=(",", ":"))


class ContextFilter(logging.Filter):
    """Injects timestamp, service, and hostname into every record."""

    def __init__(self, service: str = "ai-sentinel") -> None:
        super().__init__()
        self._service = service
        self._host = _get_hostname()

    def filter(self, record: logging.LogRecord) -> bool:
        record.service = self._service  # type: ignore[attr-defined]
        record.host = self._host  # type: ignore[attr-defined]
        return True


class RequestFilter(logging.Filter):
    """Optional filter that attaches request_id and event_id when set."""

    _request_id: str | None = None
    _event_id: str | None = None

    @classmethod
    def set_context(
        cls, request_id: str | None = None, event_id: str | None = None
    ) -> None:
        cls._request_id = request_id
        cls._event_id = event_id

    @classmethod
    def clear_context(cls) -> None:
        cls._request_id = None
        cls._event_id = None

    def filter(self, record: logging.LogRecord) -> bool:
        if self._request_id:
            record.request_id = self._request_id  # type: ignore[attr-defined]
        if self._event_id:
            record.event_id = self._event_id  # type: ignore[attr-defined]
        return True


def _get_hostname() -> str:
    try:
        return os.environ.get("HOSTNAME", os.environ.get("COMPUTERNAME", "unknown"))
    except Exception:
        return "unknown"


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the 'ai-sentinel' namespace."""
    return logging.getLogger(f"ai-sentinel.{name}")


def setup_logging(level: str = "INFO") -> None:
    """Configure the root logger with JSON output to stdout."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    root.handlers.clear()

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())

    context_filter = ContextFilter()
    request_filter = RequestFilter()

    handler.addFilter(context_filter)
    handler.addFilter(request_filter)

    root.addHandler(handler)
