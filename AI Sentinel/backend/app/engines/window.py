"""Time-window aggregation helpers used by detection rules.

Windows are computed from the persisted event store, so detections are
stateless per event, crash-safe, and reproducible.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from app import db


def window_start(minutes: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def count_events(event_type: str, since_minutes: int,
                 key_field: Optional[str] = None, key_value: Optional[str] = None) -> int:
    clauses = ["event_type = ?", "ts >= ?"]
    params = [event_type, window_start(since_minutes)]
    if key_field and key_value:
        clauses.append(f"{key_field} = ?")
        params.append(key_value)
    return db._fetch_one(f"SELECT COUNT(*) AS c FROM events WHERE {' AND '.join(clauses)}", tuple(params))["c"]


def count_events_any(event_types: list[str], since_minutes: int,
                     key_field: Optional[str] = None, key_value: Optional[str] = None,
                     extra_field: Optional[str] = None, extra_value=None) -> int:
    placeholders = ",".join("?" for _ in event_types)
    clauses = [f"event_type IN ({placeholders})", "ts >= ?"]
    params = list(event_types) + [window_start(since_minutes)]
    if key_field and key_value:
        clauses.append(f"{key_field} = ?")
        params.append(key_value)
    if extra_field is not None:
        clauses.append(f"{extra_field} = ?")
        params.append(extra_value)
    return db._fetch_one(f"SELECT COUNT(*) AS c FROM events WHERE {' AND '.join(clauses)}", tuple(params))["c"]


def distinct_values(event_type: str, since_minutes: int, field: str,
                    key_field: Optional[str] = None, key_value: Optional[str] = None) -> list[str]:
    clauses = ["event_type = ?", "ts >= ?"]
    params = [event_type, window_start(since_minutes)]
    if key_field and key_value:
        clauses.append(f"{key_field} = ?")
        params.append(key_value)
    rows = db._fetch_all(
        f"SELECT DISTINCT {field} AS v FROM events WHERE {' AND '.join(clauses)} AND {field} != ''",
        tuple(params),
    )
    return [r["v"] for r in rows]


def distinct_values_any(event_types: list[str], since_minutes: int, field: str,
                        key_field: Optional[str] = None, key_value: Optional[str] = None) -> list[str]:
    placeholders = ",".join("?" for _ in event_types)
    clauses = [f"event_type IN ({placeholders})", "ts >= ?"]
    params = list(event_types) + [window_start(since_minutes)]
    if key_field and key_value:
        clauses.append(f"{key_field} = ?")
        params.append(key_value)
    rows = db._fetch_all(
        f"SELECT DISTINCT {field} AS v FROM events WHERE {' AND '.join(clauses)} AND {field} != ''",
        tuple(params),
    )
    return [r["v"] for r in rows]
