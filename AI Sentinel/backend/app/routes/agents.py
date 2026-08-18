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


@router.post("/heartbeat")
def heartbeat(body: Heartbeat,
              agent_key: str = Header(default="", alias="X-Agent-Key")) -> dict:
    if not settings.AGENT_KEY or agent_key != settings.AGENT_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing agent key")
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
