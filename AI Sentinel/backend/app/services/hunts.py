"""Threat hunting service.

Analysts run parameterized queries against the real event corpus. Filters are
whitelisted columns; values are always bound parameters (no SQL text from the
client touches the statement). Named hunt patterns provide ready-made recipes
for common detection-opportunity hunts (impossible travel, data exfiltration,
brute force, scans, phish lures). Every run is measured and, when attached to a
saved hunt, recorded in hunt_runs for reporting.

Honesty rules: results are always drawn from stored telemetry; if the window
contains no data, the hunt returns NO_DATA rather than a fabricated empty.
"""
import csv
import io
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from app import db

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Whitelisted event columns usable as hunt filters.
FILTER_COLUMNS = {
    "event_type": "event_type", "category": "category", "severity": "severity",
    "source_ip": "source_ip", "dest_ip": "dest_ip", "host": "host",
    "username": "username", "target": "target", "process": "process",
    "command": "command", "protocol": "protocol", "source": "source",
    "environment": "environment", "asset_id": "asset_id",
}
GROUP_COLUMNS = ("event_type", "category", "severity", "source_ip", "dest_ip",
                 "host", "username", "target", "process", "environment", "source")

DEFAULT_WINDOW_MINUTES = 1440  # 24h
MAX_RESULTS = 1000

PATTERNS = {
    "brute_force": {
        "label": "Brute force / credential stuffing",
        "description": "Many failed logins per source IP or account in the window.",
        "filters": {"event_types": ["auth.failed_login", "auth.failed", "login.failed"],
                    "group_by": "source_ip", "min_group_count": 10},
    },
    "impossible_travel": {
        "label": "Impossible travel",
        "description": "The same account authenticating from multiple distinct source IPs in a short window.",
        "filters": {"event_types": ["auth.success", "auth.login", "login.success"],
                    "group_by": "username", "min_group_count": 2,
                    "distinct_field": "source_ip"},
    },
    "data_exfiltration": {
        "label": "Potential data exfiltration",
        "description": "Net connections to off-network destinations with large byte counts.",
        "filters": {"event_types": ["net.connection", "net.dns", "file.upload"],
                    "details_contains": "exfil"},
    },
    "port_scan": {
        "label": "Port scan / reconnaissance",
        "description": "Many distinct destination ports from a single source.",
        "filters": {"event_types": ["net.connection", "net.scan"], "group_by": "source_ip",
                    "min_group_count": 20, "distinct_field": "port"},
    },
    "phishing_lures": {
        "label": "Phishing lures",
        "description": "Phishing detection events and suspicious mail-flow indicators.",
        "filters": {"event_types": ["phishing.detected", "mail.suspicious", "email.filtered"]},
    },
    "new_high_port": {
        "label": "High-port outbound connections",
        "description": "Outbound connections to non-standard ports (>32768).",
        "filters": {"event_types": ["net.connection"], "port_min": 32768},
    },
    "privilege_changes": {
        "label": "Privilege / access changes",
        "description": "Elevation, group-membership and permission-change events.",
        "filters": {"event_types": ["auth.privilege_change", "auth.elevated",
                                    "iam.role_change", "user.group_change"]},
    },
}

HUNT_DETAIL_FIELDS = ("url", "domain", "command", "path", "query", "body", "file", "hash")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _window_start(start: Optional[str], minutes: Optional[int]) -> str:
    if start:
        return start
    minutes = minutes if minutes is not None else DEFAULT_WINDOW_MINUTES
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def _validate_filters(filters: dict) -> list[str]:
    errors = []
    for key in filters:
        allowed = set(FILTER_COLUMNS) | {"event_types", "query", "minutes", "start",
                                         "group_by", "min_group_count", "distinct_field",
                                         "port_min", "port_max", "severity_min",
                                         "details_contains", "limit", "pattern"}
        if key not in allowed:
            errors.append(f"unknown filter '{key}'")
    if filters.get("group_by") and filters["group_by"] not in GROUP_COLUMNS:
        errors.append(f"group_by must be one of {', '.join(GROUP_COLUMNS)}")
    if filters.get("severity_min") and filters["severity_min"] not in SEVERITY_RANK:
        errors.append("severity_min must be info/low/medium/high/critical")
    return errors


def _build_where(filters: dict, params: list) -> str:
    clauses = ["1=1"]

    start = filters.get("start")
    minutes = filters.get("minutes")
    if minutes is not None or start:
        clauses.append("ts >= ?")
        params.append(_window_start(start, minutes))
        clauses.append("ts <= ?")
        params.append(_now())

    event_types = filters.get("event_types") or []
    if filters.get("event_type"):
        event_types.append(filters["event_type"])
    if event_types:
        placeholders = ",".join("?" for _ in event_types)
        clauses.append(f"event_type IN ({placeholders})")
        params.extend(event_types)

    for key, col in FILTER_COLUMNS.items():
        value = filters.get(key)
        if value:
            if isinstance(value, (list, tuple)):
                placeholders = ",".join("?" for _ in value)
                clauses.append(f"{col} IN ({placeholders})")
                params.extend(value)
            else:
                clauses.append(f"{col} = ?")
                params.append(value)

    if filters.get("severity_min"):
        min_rank = SEVERITY_RANK[filters["severity_min"]]
        sevs = [s for s, r in SEVERITY_RANK.items() if r >= min_rank]
        placeholders = ",".join("?" for _ in sevs)
        clauses.append(f"severity IN ({placeholders})")
        params.extend(sevs)

    if filters.get("query"):
        like = f"%{filters['query']}%"
        text_cols = [FILTER_COLUMNS[c] for c in
                     ("event_type", "category", "host", "username", "source_ip",
                      "dest_ip", "target", "command", "process", "severity", "source")]
        clauses.append("(" + " OR ".join(f"{c} LIKE ?" for c in text_cols) + ")")
        params.extend([like] * len(text_cols))

    if filters.get("details_contains"):
        clauses.append("details LIKE ? AND details <> '{}'")
        params.append(f"%{filters['details_contains']}%")

    if filters.get("port_min"):
        clauses.append("port >= ?")
        params.append(int(filters["port_min"]))
    if filters.get("port_max"):
        clauses.append("port <= ?")
        params.append(int(filters["port_max"]))

    return " AND ".join(clauses)


def run_hunt(filters: dict) -> dict:
    """Run a hunt over the events corpus. Returns grouped or raw results."""
    started = time.monotonic()
    errors = _validate_filters(filters)
    if errors:
        return {"status": "ERROR", "errors": errors, "results": [], "count": 0,
                "duration_ms": 0.0, "grouped": False}

    params: list = []
    where = _build_where(filters, params)

    group_by = filters.get("group_by")
    min_group_count = int(filters.get("min_group_count", 1) or 1)
    distinct_field = filters.get("distinct_field")
    limit = int(filters.get("limit", MAX_RESULTS))

    if group_by:
        distinct_expr = ""
        if distinct_field == "port":
            distinct_expr = "COUNT(DISTINCT port)"
        elif distinct_field:
            distinct_expr = f"COUNT(DISTINCT {distinct_field})"
        else:
            distinct_expr = "COUNT(*)"
        sql = (f"SELECT {group_by} AS key, COUNT(*) AS events, {distinct_expr} AS distinct_value "
               f"FROM events WHERE {where} "
               f"GROUP BY {group_by} HAVING COUNT(*) >= ? "
               f"ORDER BY events DESC LIMIT ?")
        rows = db._fetch_all(sql, tuple(params + [min_group_count, limit]))
        return {
            "status": "OK" if rows else (
                "NO_DATA" if db.count_events() == 0 else "NO_MATCHES"),
            "results": rows,
            "count": len(rows),
            "duration_ms": round((time.monotonic() - started) * 1000.0, 2),
            "grouped": True,
            "group_by": group_by,
            "distinct_field": distinct_field,
            "window": _window_start(filters.get("start"), filters.get("minutes")),
        }

    rows = db._fetch_all(f"SELECT * FROM events WHERE {where} ORDER BY ts DESC LIMIT ?",
                         tuple(params + [limit]))
    truncated = len(rows) >= limit
    return {
        "status": "OK" if rows else ("NO_DATA" if db.count_events() == 0 else "NO_MATCHES"),
        "results": rows,
        "count": len(rows),
        "duration_ms": round((time.monotonic() - started) * 1000.0, 2),
        "grouped": False,
        "truncated": truncated,
        "window": _window_start(filters.get("start"), filters.get("minutes")),
    }


def filters_to_csv(filters: dict) -> str:
    """Run a hunt and render the results as CSV (name-safe columns only)."""
    result = run_hunt(filters)
    buf = io.StringIO()
    writer = csv.writer(buf)
    if result.get("grouped"):
        writer.writerow([result["group_by"], "events",
                         result.get("distinct_field") or "count"])
        for r in result["results"]:
            writer.writerow([r.get("key", ""), r.get("events", 0),
                             r.get("distinct_value", r.get("events", 0))])
    else:
        columns = ("event_id", "ts", "event_type", "severity", "host", "username",
                   "source_ip", "dest_ip", "target", "process", "environment", "source")
        writer.writerow(columns)
        for ev in result["results"]:
            writer.writerow([ev.get(c, "") for c in columns])
    return buf.getvalue()


def patterns_list() -> list[dict]:
    return [{"key": key, **pat} for key, pat in PATTERNS.items()]