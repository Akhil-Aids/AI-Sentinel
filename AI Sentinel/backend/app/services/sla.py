"""Incident SLA engine.

SLA state is computed from the incident's creation time, its severity target and
current status — never assumed:
  MET          - resolved before the target elapsed
  WITHIN_SLA   - remaining time > 25% of target
  APPROACHING  - 25% or less of target remaining
  BREACHED     - target elapsed while still active
Computation is time-based so states roll correctly over time.
"""
from datetime import datetime, timezone

from app import db

RESOLVED_STATUSES = {"RESOLVED", "FALSE_POSITIVE"}

SLA_STATES = ("MET", "WITHIN_SLA", "APPROACHING", "BREACHED", "SLA_PAUSED", "NO_TARGET")


def _dt(value: str) -> float:
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except Exception:
        return 0.0


def target_minutes_for(severity: str) -> int | None:
    policy = db.get_sla_policy(severity)
    if not policy or not policy.get("enabled"):
        return None
    return int(policy["target_minutes"])


def compute_sla(incident: dict) -> dict:
    if not incident:
        return {"status": "NO_TARGET", "state": "NO_TARGET"}
    target = target_minutes_for(incident.get("severity", "medium"))
    if target is None:
        return {"status": "NO_TARGET", "target_minutes": None,
                "state": "NO_TARGET", "detail": "No enabled SLA policy for this severity"}
    created = _dt(incident.get("created_at", ""))
    if not created:
        return {"status": "UNKNOWN", "target_minutes": target,
                "state": "SLA_PAUSED", "detail": "Missing creation timestamp"}
    now = datetime.now(timezone.utc).timestamp()
    elapsed = max(0.0, now - created)
    elapsed_min = round(elapsed / 60, 1)
    remaining = target * 60 - elapsed
    remaining_min = round(remaining / 60, 1)
    resolved_at = incident.get("resolved_at")
    resolved_elapsed = round((_dt(resolved_at) - created) / 60, 1) if resolved_at else None

    status = incident.get("status", "NEW")
    if status in RESOLVED_STATUSES:
        state = "MET" if resolved_elapsed is not None and resolved_elapsed <= target else "BREACHED"
    elif remaining <= 0:
        state = "BREACHED"
    elif remaining <= target * 60 * 0.25:
        state = "APPROACHING"
    else:
        state = "WITHIN_SLA"
    return {
        "state": state,
        "target_minutes": target,
        "elapsed_minutes": elapsed_min,
        "remaining_minutes": max(0.0, remaining_min) if state in ("WITHIN_SLA", "APPROACHING") else 0.0,
        "resolved_elapsed_minutes": resolved_elapsed,
        "status": status,
    }


def sla_for_incidents(incidents: list[dict]) -> list[dict]:
    result = []
    for inc in incidents:
        result.append({**inc, "sla": compute_sla(inc)})
    return result


def sla_summary() -> dict:
    incidents = db.list_incidents(limit=500)
    counted = {"WITHIN_SLA": 0, "APPROACHING": 0, "BREACHED": 0, "MET": 0, "NO_TARGET": 0}
    for inc in incidents:
        state = compute_sla(inc)["state"]
        counted[state] = counted.get(state, 0) + 1
    return {"by_state": counted, "total": len(incidents),
            "breach_rate": round(counted["BREACHED"] / len(incidents), 3) if incidents else 0.0}