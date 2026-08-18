"""Event normalization.

Turns raw telemetry from any source (agents, collectors, integrations) into a
canonical security event with a stable schema and default severity.

Canonical fields are always present:
  event_id, ts (UTC ISO-8601), source, source_type, host, environment,
  asset_id, is_simulated, event_type, category, severity, confidence,
  risk_score, details, mitre, normalized_at, raw.

Missing values are `None` / empty — never fabricated.
"""
from datetime import datetime, timezone

from app.core.config import settings

SEVERITIES = ("info", "low", "medium", "high", "critical")

# Mapping from source-specific raw field names to canonical fields.
_FIELD_MAP = {
    "src_ip": "source_ip", "source": "source_ip", "sip": "source_ip",
    "dst_ip": "dest_ip", "dest_ip": "dest_ip", "target_ip": "dest_ip", "dip": "dest_ip",
    "src_port": "source_port", "dst_port": "port", "dest_port": "port", "port": "port",
    "user": "username", "account": "username", "username": "username",
    "proc": "process", "process": "process", "process_name": "process",
    "cmd": "command", "command_line": "command", "command": "command",
    "hostname": "host", "host": "host",
    "msg": "description", "description": "description",
}


def _normalize_ts(value) -> str:
    """Coerce a timestamp to a UTC ISO-8601 string with a +00:00 offset.

    Raw timestamps may arrive with a Z suffix (which SQLite string comparison
    orders after non-Z values) or with any timezone offset. Windowed queries
    rely on consistent ordering, so we canonicalize to `+00:00`.
    """
    if value is None or value == "":
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, (int, float)):
        # Unix epoch seconds/milliseconds.
        if value > 10_000_000_000:
            value = value / 1000.0
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        return datetime.now(timezone.utc).isoformat()


def normalize_raw(raw: dict, source: str = "agent") -> dict:
    """Normalize a raw dict (from agent, integration, collector) into a canonical event."""
    ev: dict = {}
    for k, v in raw.items():
        key = _FIELD_MAP.get(k, k)
        ev[key] = v

    ev["source"] = source
    ev["source_type"] = raw.get("source_type") or _source_type_for(source)
    ev["ts"] = _normalize_ts(raw.get("ts") or raw.get("timestamp"))
    ev["event_type"] = ev.get("event_type") or ev.get("type") or "unknown"
    ev["category"] = ev.get("category") or ev.get("event_category") or _category_for(ev["event_type"])
    ev["environment"] = raw.get("environment") or ev.get("environment") or settings.ENVIRONMENT
    ev["asset_id"] = raw.get("asset_id") or ev.get("asset_id") or ev.get("host") or ""
    ev["is_simulated"] = 1 if raw.get("is_simulated") or ev.get("is_simulated") or raw.get("mode") == "simulation" else 0

    severity = str(ev.get("severity", "info")).lower()
    ev["severity"] = severity if severity in SEVERITIES else "medium"
    ev["confidence"] = float(ev.get("confidence", 0.0) or 0.0)
    ev["risk_score"] = int(ev.get("risk_score", 0) or 0)

    details = ev.get("details")
    ev["details"] = details if isinstance(details, dict) else {}
    ev["mitre"] = ev.get("mitre", [])
    if not isinstance(ev["mitre"], list):
        ev["mitre"] = []

    # Track when this normalization step ran (used for latency instrumentation).
    ev["normalized_at"] = datetime.now(timezone.utc).isoformat()

    # Keep a copy of the raw payload.
    ev["raw"] = dict(raw)
    return ev


def _source_type_for(source: str) -> str:
    t = str(source).lower()
    if t in {"collector", "agent", "integration", "api"}:
        return t
    return "telemetry"


def _category_for(event_type: str) -> str:
    t = event_type.lower()
    if "auth" in t or "login" in t:
        return "authentication"
    if "network" in t or "connection" in t or "flow" in t:
        return "network"
    if "file" in t or "filesystem" in t:
        return "file"
    if "process" in t or "proc" in t:
        return "process"
    if "web" in t or "http" in t or "request" in t:
        return "application"
    if "phish" in t:
        return "phishing"
    if "user" in t or "account" in t or "privilege" in t:
        return "identity"
    return "system"
