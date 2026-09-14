"""Explainable user and asset risk scoring.

Computes 0-100 risk summaries from *real* stored telemetry:

  * per-user: events referencing the user, high/critical event volume, and
    open incidents tied to the user.
  * per-asset: events on the host, high/critical event volume, and open
    incidents tied to the host.

Each score is accompanied by an explicit list of `factors` (what contributed
and by how much) so an analyst can see exactly why a score moved. Scores are
cached in the `user_risk` / `asset_risk` tables and recomputed on access when
stale (never on the hot path).
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from app import db
from app.core.config import settings
from app.risk import combine_risks, event_risk, risk_level

WINDOW_DAYS = 30
OPEN_STATUSES = ("NEW", "INVESTIGATING", "CONTAINED")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _window_start() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)).isoformat()


def _stale(row: Optional[dict]) -> bool:
    if not row:
        return True
    try:
        calc = datetime.fromisoformat(row["calculated_at"])
    except Exception:
        return True
    return (datetime.now(timezone.utc) - calc).total_seconds() > settings.RISK_CACHE_TTL_SECONDS


def _severity_rank(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 0)


def _events_for_user(username: str):
    return db._fetch_all(
        "SELECT severity, confidence, event_type FROM events WHERE username = ? AND ts >= ?",
        (username, _window_start()),
    )


def _events_for_asset(host: str):
    return db._fetch_all(
        "SELECT severity, confidence, event_type FROM events WHERE host = ? AND ts >= ?",
        (host, _window_start()),
    )


def _incidents_for_user(username: str):
    return db._fetch_all(
        "SELECT severity, risk_score, status FROM incidents WHERE affected_user = ? AND status IN ('NEW','INVESTIGATING','CONTAINED')",
        (username,),
    )


def _incidents_for_asset(host: str):
    return db._fetch_all(
        "SELECT severity, risk_score, status FROM incidents WHERE affected_host = ? AND status IN ('NEW','INVESTIGATING','CONTAINED')",
        (host,),
    )


def _factors_from(events: list, incidents: list, volume_cap: int) -> tuple[list, int, float]:
    event_scores = [event_risk({"severity": e.get("severity", "info"),
                                "confidence": e.get("confidence", 0.0)}) for e in events]
    severe = [e for e in events if _severity_rank(e.get("severity", "")) >= 3]
    factors: list[dict] = []
    if events:
        factors.append({
            "factor": "event_volume",
            "effect": round(min(40.0, 5.0 * (len(events) / 10.0)), 1),
            "detail": f"{len(events)} events in the last {WINDOW_DAYS} days",
        })
    if severe:
        factors.append({
            "factor": "high_critical_events",
            "effect": round(min(30.0, len(severe) * 6.0), 1),
            "detail": f"{len(severe)} high/critical severity events",
        })
    score = round(combine_risks(event_scores), 1) if event_scores else 0.0
    score = min(score + sum(f["effect"] for f in factors), 100.0)
    incident_factor = 0.0
    if incidents:
        max_open = max(int(i.get("risk_score", 0) or 0) for i in incidents)
        incident_factor = min(40.0, 0.5 * max_open + 5 * len(incidents))
        factors.append({
            "factor": "open_incidents",
            "effect": round(incident_factor, 1),
            "detail": f"{len(incidents)} open incident(s), max risk {max_open}",
        })
    total = min(100.0, score + incident_factor)
    return factors, len(events), total, len(severe)


def compute_user_risk(username: str, force: bool = False) -> dict:
    cached = db.get_user_risk(username)
    if not force and cached and not _stale(cached) and cached.get("risk_factors"):
        return cached
    events = _events_for_user(username)
    incidents = _incidents_for_user(username)
    factors, ev_count, total, severe_count = _factors_from(events, incidents, 40)
    last_event = events[0] if events else None
    last_event_at = _now() if last_event else ""
    score = int(round(total))
    level = risk_level(score)
    db.save_user_risk(username, score, level, factors, ev_count,
                      severe_count, len(incidents), last_event_at)
    return db.get_user_risk(username)


def compute_asset_risk(hostname: str, force: bool = False) -> dict:
    cached = db.get_asset_risk(hostname)
    if not force and cached and not _stale(cached) and cached.get("risk_factors"):
        return cached
    events = _events_for_asset(hostname)
    incidents = _incidents_for_asset(hostname)
    factors, ev_count, total, severe_count = _factors_from(events, incidents, 40)
    last_event = events[0] if events else None
    last_event_at = _now() if last_event else ""
    score = int(round(total))
    level = risk_level(score)
    db.save_asset_risk(hostname, score, level, factors, ev_count,
                       severe_count, len(incidents), last_event_at)
    return db.get_asset_risk(hostname)


def recompute_all_users() -> int:
    rows = db._fetch_all(
        "SELECT DISTINCT username FROM events WHERE username <> '' AND ts >= ?",
        (_window_start(),),
    )
    count = 0
    for r in rows:
        compute_user_risk(r["username"], force=True)
        count += 1
    inc_users = db._fetch_all(
        "SELECT DISTINCT affected_user FROM incidents WHERE affected_user <> ''")
    for r in inc_users:
        compute_user_risk(r["affected_user"], force=True)
        count += 1
    return count


def recompute_all_assets() -> int:
    rows = db._fetch_all(
        "SELECT DISTINCT host FROM events WHERE host <> '' AND ts >= ?",
        (_window_start(),),
    )
    count = 0
    for r in rows:
        compute_asset_risk(r["host"], force=True)
        count += 1
    inc_hosts = db._fetch_all(
        "SELECT DISTINCT affected_host FROM incidents WHERE affected_host <> ''")
    for r in inc_hosts:
        compute_asset_risk(r["affected_host"], force=True)
        count += 1
    return count