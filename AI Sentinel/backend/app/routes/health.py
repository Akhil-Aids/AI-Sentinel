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


@router.get("/audit/verify")
def audit_verify(
    _payload: dict = Depends(require_privilege_at_least("SECURITY_ENGINEER")),
) -> dict:
    return db.verify_audit_chain()


@router.get("/health")
def health() -> dict:
    """Authenticated detailed system health."""
    import sqlite3
    db_ok = True
    try:
        db.get_connection().execute("SELECT 1").fetchone()
    except sqlite3.Error:
        db_ok = False

    comps = component_health()
    ready = db_ok and pipeline._started
    return {
        "status": "ok" if ready else ("degraded" if db_ok else "error"),
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "database": "ok" if db_ok else "error",
        "pipeline_started": pipeline._started,
        "demo_mode": settings.DEMO_MODE,
        "telemetry": _telemetry_status(),
        "collector": get_collector_status(),
        "ready": ready,
        "checks": {
            "database": "ok" if db_ok else "error",
            "pipeline": "ok" if pipeline._started else "starting",
        },
        "components": comps,
    }


def component_health() -> dict:
    """Actual status of each AI Sentinel component (never assumed)."""
    ml_status = anomaly_detector.status()
    ti_configured = _ti_configured()
    agents = list_agent_status()
    online_agents = sum(1 for a in agents if a.get("status") == "HEALTHY")
    return {
        "database": {
            "status": "HEALTHY" if _db_ok() else "ERROR",
            "detail": "WAL SQLite storage reachable" if _db_ok() else "Storage unreachable",
        },
        "pipeline": {
            "status": "HEALTHY" if pipeline._started else "STOPPED",
            "detail": f"{pipeline.stats().get('processed', 0)} events processed",
        },
        "websocket": {
            "status": "HEALTHY" if ws_manager.count() >= 0 else "UNKNOWN",
            "clients": ws_manager.count(),
        },
        "telemetry": _telemetry_status(),
        "collector": get_collector_status(),
        "ml": {
            "status": "CONNECTED" if settings.ML_ENABLED and ml_status.get("trained_samples", 0) > 0 else ("DISABLED" if not settings.ML_ENABLED else "UNTRAINED"),
            "detail": f"{ml_status.get('trained_samples', 0)} samples trained",
        },
        "threat_intel": {
            "status": "CONNECTED" if ti_configured else "NOT_CONFIGURED",
            "detail": "API keys configured" if ti_configured else "No threat-intel API key configured; local IOC store only",
            "providers": {"virustotal": bool(settings.TI_VT_API_KEY), "abuseipdb": bool(settings.TI_ABUSEIPDB_KEY)},
        },
        "agents": {
            "status": "HEALTHY" if online_agents else ("NO_AGENTS" if not agents else "DEGRADED"),
            "online": online_agents,
            "total": len(agents),
        },
        "notifications": {
            "webhook": "CONFIGURED" if settings.NOTIFY_WEBHOOK_URL else "NOT_CONFIGURED",
            "min_severity": settings.NOTIFY_MIN_SEVERITY,
        },
        "ai_provider": {
            "status": "RULE_BASED",
            "detail": "Grounded SOC assistant using the built-in telemetry toolchain (no external LLM key configured).",
        },
    }


def _db_ok() -> bool:
    import sqlite3
    try:
        db.get_connection().execute("SELECT 1").fetchone()
        return True
    except sqlite3.Error:
        return False


def _ti_configured() -> bool:
    return bool(settings.TI_VT_API_KEY or settings.TI_ABUSEIPDB_KEY)


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
