"""Agent heartbeat and health routes.

Endpoint agents push telemetry with the shared agent key. They also send
heartbeats here. Status is derived from heartbeat age:
  HEALTHY   - heartbeat within AGENT_DEGRADED_SECONDS
  DEGRADED  - within AGENT_OFFLINE_SECONDS
  OFFLINE   - older
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from app import db
from app.core.config import settings
from app.core.deps import current_user
from app.telemetry.collector import agent_id as collector_agent_id

router = APIRouter()


class Heartbeat(BaseModel):
    agent_id: str = Field(min_length=3, max_length=128)
    hostname: str = ""
    ip: str = ""
    os: str = ""
    environment: str = ""
    version: str = ""
    cpu: float = 0.0
    memory: float = 0.0
    disk: float = 0.0
    processes: int = 0


def _agent_auth(agent_key: str, api_key: str) -> None:
    """Accept the legacy shared agent key OR a managed API key (scope ingest)."""
    from app.core import apikey as apikey_core
    if settings.AGENT_KEY and agent_key and agent_key == settings.AGENT_KEY:
        return
    if api_key:
        parts = apikey_core.parse_header(api_key)
        if parts:
            record = verify_api_key_helper(parts[0], parts[1])
            if record:
                return
    raise HTTPException(status_code=401, detail="Invalid or missing agent credentials")


def verify_api_key_helper(key_id: str, secret: str):
    """Validate API key credentials, returning the key record or None."""
    from app.core import apikey as apikey_core
    from datetime import datetime, timezone
    record = db.get_api_key_auth(key_id)
    if not record:
        return None
    if record.get("revoked_at"):
        return None
    if record.get("expires_at"):
        try:
            exp = datetime.fromisoformat(record["expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                return None
        except Exception:
            return None
    if not apikey_core.verify_digest(key_id, secret, record.get("key_hash", "")):
        return None
    allowed_scopes = [s.strip() for s in (record.get("scope") or "").split(",") if s.strip()]
    if "ingest" not in allowed_scopes and "admin" not in allowed_scopes:
        return None
    db.touch_api_key_last_used(key_id)
    return record


@router.post("/heartbeat")
def heartbeat(body: Heartbeat,
              agent_key: str = Header(default="", alias="X-Agent-Key"),
              api_key: str = Header(default="", alias="X-API-Key")) -> dict:
    _agent_auth(agent_key, api_key)
    agent = db.upsert_agent_heartbeat(body.agent_id, {
        "hostname": body.hostname,
        "ip": body.ip,
        "os": body.os,
        "environment": body.environment or settings.ENVIRONMENT,
        "version": body.version,
        "status": "HEALTHY",
    })
    if body.hostname:
        db.upsert_server(body.hostname, {
            "ip": body.ip, "os": body.os, "status": "online",
            "cpu": body.cpu, "memory": body.memory, "disk": body.disk,
            "processes": body.processes, "environment": body.environment or settings.ENVIRONMENT,
            "agent_id": body.agent_id,
        })
    return {"status": "ok", "agent_id": body.agent_id, "last_heartbeat_at": agent["last_heartbeat_at"]}


def _age_seconds(last_heartbeat_at: str) -> float:
    try:
        last = datetime.fromisoformat(last_heartbeat_at)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - last).total_seconds())
    except Exception:
        return float("inf")


def agent_status(last_heartbeat_at: str) -> str:
    age = _age_seconds(last_heartbeat_at)
    if age <= settings.AGENT_DEGRADED_SECONDS:
        return "HEALTHY"
    if age <= settings.AGENT_OFFLINE_SECONDS:
        return "DEGRADED"
    return "OFFLINE"


def list_agent_status() -> list[dict]:
    out = []
    for a in db.list_agents():
        status = agent_status(a["last_heartbeat_at"])
        out.append({
            "agent_id": a["agent_id"],
            "hostname": a.get("hostname", ""),
            "ip": a.get("ip", ""),
            "os": a.get("os", ""),
            "environment": a.get("environment", ""),
            "version": a.get("version", ""),
            "status": status,
            "last_heartbeat_at": a["last_heartbeat_at"],
            "heartbeat_age_seconds": round(_age_seconds(a["last_heartbeat_at"]), 1),
        })
    return out


@router.get("/")
def list_agents(_payload: dict = Depends(current_user)) -> dict:
    return {"items": list_agent_status(),
            "degraded_after_s": settings.AGENT_DEGRADED_SECONDS,
            "offline_after_s": settings.AGENT_OFFLINE_SECONDS}


@router.get("/collector")
def collector_info(_payload: dict = Depends(current_user)) -> dict:
    """Resolve the built-in collector agent id for this host."""
    return {"agent_id": collector_agent_id()}
