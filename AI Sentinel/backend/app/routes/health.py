"""Audit and observability routes."""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app import db
from app.core.config import settings
from app.core.deps import current_user, require_privilege_at_least
from app.ml.anomaly import anomaly_detector
from app.pipeline import pipeline
from app.services.ws_manager import ws_manager
from app.routes.agents import list_agent_status
from app.telemetry.collector import get_collector_status

router = APIRouter()


@router.get("/audit")
def audit_logs(
    limit: int = Query(200, ge=1, le=1000),
    actor: Optional[str] = None,
    _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST")),
) -> dict:
    return {"items": db.list_audit(limit=limit, actor=actor)}


@router.get("/health")
def health() -> dict:
    """Public health check (no auth) for load balancers / orchestrators."""
    import sqlite3
    db_ok = True
    try:
        db.get_connection().execute("SELECT 1").fetchone()
    except sqlite3.Error:
        db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "database": "ok" if db_ok else "error",
        "pipeline_started": pipeline._started,
        "telemetry": _telemetry_status(),
        "collector": get_collector_status(),
    }


def _telemetry_status() -> dict:
    """Telemetry staleness: is the collector currently producing data?"""
    servers = db.list_servers()
    if not servers:
        return {"status": "NO_DATA", "detail": "No server telemetry received yet"}
    newest = None
    for s in servers:
        seen = s.get("last_seen_at")
        if seen and (newest is None or seen > newest):
            newest = seen
    if not newest:
        return {"status": "NO_DATA", "detail": "No server telemetry received yet"}
    try:
        last = datetime.fromisoformat(newest)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        age = max(0.0, (datetime.now(timezone.utc) - last).total_seconds())
    except Exception:
        return {"status": "UNKNOWN", "detail": "Could not parse last seen timestamp"}
    if age <= settings.METRICS_INTERVAL * 3:
        return {"status": "OK", "age_seconds": round(age, 1)}
    if age <= settings.AGENT_OFFLINE_SECONDS:
        return {"status": "STALE", "age_seconds": round(age, 1)}
    return {"status": "NO_DATA", "age_seconds": round(age, 1)}


@router.get("/metrics")
def metrics(_payload: dict = Depends(current_user)) -> dict:
    """Internal system-health / observability dashboard data."""
    counts = db.stats_counts()
    return {
        "storage": counts,
        "pipeline": pipeline.stats(),
        "ml": anomaly_detector.status(),
        "websocket_clients": ws_manager.serialize(),
        "queue": {"depth": pipeline.queue_depth(), "maxsize": settings.QUEUE_MAXSIZE},
        "agents": list_agent_status(),
        "telemetry": _telemetry_status(),
        "collector": get_collector_status(),
        "backup_protection": {"targets": settings.BACKUP_TARGETS},
        "config": {
            "env": settings.ENV,
            "environment": settings.ENVIRONMENT,
            "workers": settings.WORKER_CONSUMERS,
            "retention_days": settings.RETENTION_DAYS,
            "ml_enabled": settings.ML_ENABLED,
            "ti_enabled": settings.TI_ENABLED,
            "response_dry_run": settings.RESPONSE_DRY_RUN,
            "demo_mode": settings.DEMO_MODE,
            "latency_target_event_ms": settings.LATENCY_TARGET_EVENT_MS,
            "latency_target_critical_ms": settings.LATENCY_TARGET_CRITICAL_MS,
        },
    }


@router.post("/retention/apply")
def apply_retention(_payload: dict = Depends(require_privilege_at_least("ADMIN"))) -> dict:
    result = db.apply_retention(settings.RETENTION_DAYS)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="retention.apply",
                 result="SUCCESS", detail=result)
    return {"status": "ok", "deleted": result}
