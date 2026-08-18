"""Event ingestion and query routes.

Agents may authenticate with a shared agent key (SENTINEL_AGENT_KEY) via the
X-Agent-Key header, or with a user bearer token. User ingestion is gated to
analyst-or-higher roles; agents use the key path.
"""
import time
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel

from app import db
from app.core.config import settings
from app.core.deps import client_ip, current_user, require_privilege_at_least
from app.pipeline import pipeline

router = APIRouter()

MAX_BATCH_EVENTS = 1000
MAX_FIELD_LEN = 4096
KNOWN_EVENT_TYPES = None  # any string is accepted; unknown types are tagged


class EventBatch(BaseModel):
    events: list[dict]


def _validate_raw(raw: dict) -> str | None:
    """Validate a raw event; returns an error message or None."""
    if not isinstance(raw, dict) or not raw:
        return "event must be a non-empty object"
    if len(raw) > 64:
        return "event has too many fields"
    for k, v in raw.items():
        if not isinstance(k, str) or len(k) > 128:
            return "invalid field name"
        if isinstance(v, str) and len(v) > MAX_FIELD_LEN:
            return f"field '{k}' exceeds max length"
        if isinstance(v, (dict, list)) and len(str(v)) > 65536:
            return f"field '{k}' too large"
    et = str(raw.get("event_type") or raw.get("type") or "unknown")
    if len(et) > 128:
        return "event_type too long"
    return None


@router.post("/ingest")
def ingest_events(
    batch: EventBatch,
    request: Request,
    _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST")),
) -> dict:
    """Accept a batch of raw events from an authenticated analyst. Non-blocking."""
    if len(batch.events) > MAX_BATCH_EVENTS:
        raise HTTPException(status_code=400,
                            detail=f"Batch exceeds limit of {MAX_BATCH_EVENTS} events")
    accepted, dropped, rejected = 0, 0, 0
    for raw in batch.events:
        err = _validate_raw(raw)
        if err:
            rejected += 1
            continue
        source = raw.get("source", "agent")
        if pipeline.ingest(raw, source=source):
            accepted += 1
        else:
            dropped += 1
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="events.ingest",
                 result="SUCCESS", ip=client_ip(request),
                 detail={"accepted": accepted, "dropped": dropped, "rejected": rejected,
                         "simulated": sum(1 for e in batch.events if e.get("is_simulated") or e.get("mode") == "simulation")})
    return {"accepted": accepted, "dropped": dropped, "rejected": rejected}


@router.post("/ingest/agent")
def ingest_agent_events(
    batch: EventBatch,
    request: Request,
    agent_key: Optional[str] = Header(default=None, alias="X-Agent-Key"),
) -> dict:
    """Agent-only ingestion using the shared agent key (no user token)."""
    if not settings.AGENT_KEY or agent_key != settings.AGENT_KEY:
        db.log_audit(actor="agent", action="events.ingest_agent", result="FAILED",
                     ip=client_ip(request), detail={"reason": "invalid agent key"})
        raise HTTPException(status_code=401, detail="Invalid or missing agent key")
    if len(batch.events) > MAX_BATCH_EVENTS:
        raise HTTPException(status_code=400,
                            detail=f"Batch exceeds limit of {MAX_BATCH_EVENTS} events")
    accepted, dropped, rejected = 0, 0, 0
    for raw in batch.events:
        err = _validate_raw(raw)
        if err:
            rejected += 1
            continue
        source = raw.get("source", "agent")
        if pipeline.ingest(raw, source=source):
            accepted += 1
        else:
            dropped += 1
    db.log_audit(actor="agent", action="events.ingest_agent", result="SUCCESS",
                 ip=client_ip(request), detail={"accepted": accepted, "dropped": dropped, "rejected": rejected})
    return {"accepted": accepted, "dropped": dropped, "rejected": rejected}


@router.get("/")
def list_events(
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    host: Optional[str] = None,
    environment: Optional[str] = None,
    _payload: dict = Depends(current_user),
) -> dict:
    items = db.list_events(limit=limit, event_type=event_type, severity=severity,
                           source_ip=source_ip, host=host, environment=environment)
    return {"items": items, "total": db.count_events()}


@router.get("/{event_id}")
def event_detail(event_id: str, _payload: dict = Depends(current_user)) -> dict:
    ev = db.get_event_by_id(event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    return ev
