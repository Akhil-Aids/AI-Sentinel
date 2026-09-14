"""SOC operational metrics computed from real telemetry.

Implements the standard SOC KPIs where sufficient data exists:

  MTTD - mean time to detect: event occurrence (ts) -> engine detection.
  MTTA - mean time to acknowledge: alert/incident created -> acknowledged.
  MTTR - mean time to respond/acknowledge on incidents (create -> acknowledge).
  MTT R - mean time to resolve: incident created -> resolved.

Values are only reported when real samples exist; otherwise the metric is
`None` rather than a fabricated zero. All durations are minutes.
"""
from datetime import datetime, timedelta, timezone
from statistics import mean
from typing import Optional

from app import db


def _parse(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _minutes(start: datetime, end: datetime) -> float:
    return max(0.0, (end - start).total_seconds() / 60.0)


def _bucket(seconds: float) -> Optional[float]:
    return round(seconds, 2)


def _mean_minutes(samples: list[float]):
    if not samples:
        return None
    return round(mean(samples), 2)


def mean_time_to_detect(days: int = 7) -> dict:
    """MTTD per detection: event ts -> detected_at, over recent events."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = db._fetch_all(
        "SELECT ts, detected_at FROM events WHERE detected_at IS NOT NULL AND ts >= ? ORDER BY ts DESC LIMIT 500",
        (since,),
    )
    samples = []
    for r in rows:
        start, end = _parse(r["ts"]), _parse(r["detected_at"])
        if start and end:
            samples.append(_minutes(start, end))
    return {"metric": "mttd", "label": "Mean Time To Detect",
            "minutes": _mean_minutes(samples), "samples": len(samples),
            "unit": "minutes"}


def mean_time_to_acknowledge(days: int = 30) -> dict:
    """MTTA across alerts and incidents that were acknowledged."""
    samples: list[float] = []
    alert_rows = db._fetch_all(
        "SELECT created_at, acknowledged_at FROM alerts WHERE acknowledged_at IS NOT NULL AND created_at >= ?",
        ((datetime.now(timezone.utc) - timedelta(days=days)).isoformat(),),
    )
    for r in alert_rows:
        start, end = _parse(r["created_at"]), _parse(r["acknowledged_at"])
        if start and end:
            samples.append(_minutes(start, end))
    inc_rows = db._fetch_all(
        "SELECT created_at, acknowledged_at FROM incidents WHERE acknowledged_at IS NOT NULL AND created_at >= ?",
        ((datetime.now(timezone.utc) - timedelta(days=days)).isoformat(),),
    )
    for r in inc_rows:
        start, end = _parse(r["created_at"]), _parse(r["acknowledged_at"])
        if start and end:
            samples.append(_minutes(start, end))
    return {"metric": "mtta", "label": "Mean Time To Acknowledge",
            "minutes": _mean_minutes(samples), "samples": len(samples),
            "unit": "minutes"}


def mean_time_to_respond(days: int = 30) -> dict:
    """MTTR (respond): incident created -> first acknowledged, incident-scoped."""
    rows = db._fetch_all(
        "SELECT created_at, acknowledged_at FROM incidents WHERE acknowledged_at IS NOT NULL AND created_at >= ?",
        ((datetime.now(timezone.utc) - timedelta(days=days)).isoformat(),),
    )
    samples = []
    for r in rows:
        start, end = _parse(r["created_at"]), _parse(r["acknowledged_at"])
        if start and end:
            samples.append(_minutes(start, end))
    return {"metric": "mttr_respond", "label": "Mean Time To Respond",
            "minutes": _mean_minutes(samples), "samples": len(samples),
            "unit": "minutes"}


def mean_time_to_resolve(days: int = 30) -> dict:
    """MTTR (resolve): incident created -> resolved."""
    rows = db._fetch_all(
        "SELECT created_at, resolved_at FROM incidents WHERE resolved_at IS NOT NULL AND created_at >= ?",
        ((datetime.now(timezone.utc) - timedelta(days=days)).isoformat(),),
    )
    samples = []
    for r in rows:
        start, end = _parse(r["created_at"]), _parse(r["resolved_at"])
        if start and end:
            samples.append(_minutes(start, end))
    return {"metric": "mttr", "label": "Mean Time To Resolve",
            "minutes": _mean_minutes(samples), "samples": len(samples),
            "unit": "minutes"}


def soc_metrics(days: int = 30) -> dict:
    """Aggregate SOC KPI block for dashboards and reports."""
    return {
        "mttd": mean_time_to_detect(days=7),
        "mtta": mean_time_to_acknowledge(days=days),
        "mttr_respond": mean_time_to_respond(days=days),
        "mttr_resolve": mean_time_to_resolve(days=days),
        "window_days": days,
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }