"""Incident SLA routes: policies CRUD + live per-incident SLA state."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app import db
from app.core.deps import require_privilege_at_least
from app.services import sla as sla_service

router = APIRouter()

SEVERITIES = ("info", "low", "medium", "high", "critical")


class SlaPolicyRequest(BaseModel):
    target_minutes: int = Field(ge=1, le=100000)
    enabled: bool = True


@router.get("/policies/")
def list_policies(_payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    return {"items": db.list_sla_policies()}


@router.put("/policies/{severity}")
def update_policy(severity: str, body: SlaPolicyRequest,
                  _payload: dict = Depends(require_privilege_at_least("ADMIN"))) -> dict:
    if severity not in SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Severity must be one of {', '.join(SEVERITIES)}")
    policy = db.upsert_sla_policy(severity, body.target_minutes, body.enabled)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="sla.policy_update",
                 target=severity, detail={"target_minutes": body.target_minutes, "enabled": body.enabled})
    return policy


@router.get("/incidents/")
def incidents_sla(limit: int = 200,
                  _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    incidents = db.list_incidents(limit=limit)
    return {"items": sla_service.sla_for_incidents(incidents),
            "summary": sla_service.sla_summary()}


@router.get("/incidents/{incident_id}")
def incident_sla(incident_id: str,
                 _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    inc = db.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return sla_service.compute_sla(inc)