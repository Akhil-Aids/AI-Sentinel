"""Incident routes: list, detail, update status, response actions."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from app import db
from app.core.deps import client_ip, current_user, require_privilege_at_least
from app.response import ACTION_LABELS, response_engine

router = APIRouter()

VALID_STATUSES = {"NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"}


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    analyst_notes: Optional[str] = None
    recovery_status: Optional[str] = None


class ResponseActionRequest(BaseModel):
    action: str
    reason: str = ""


@router.get("/")
def list_incidents(
    limit: int = Query(100, ge=1, le=500),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    _payload: dict = Depends(current_user),
) -> dict:
    return {"items": db.list_incidents(limit=limit, status=status, severity=severity)}


@router.get("/{incident_id}")
def incident_detail(incident_id: str, _payload: dict = Depends(current_user)) -> dict:
    inc = db.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    # Attach the underlying events for the timeline.
    events = []
    for eid in inc.get("event_ids", [])[:200]:
        ev = db.get_event_by_id(eid)
        if ev:
            events.append(ev)
    inc["_events"] = events
    return inc


@router.patch("/{incident_id}")
def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    request: Request,
    _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST")),
) -> dict:
    inc = db.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    fields = {}
    if body.status:
        if body.status not in VALID_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status")
        fields["status"] = body.status
    if body.analyst_notes is not None:
        fields["analyst_notes"] = body.analyst_notes
    if body.recovery_status is not None:
        fields["recovery_status"] = body.recovery_status
    db.update_incident(incident_id, **fields)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="incident.update",
                 target=incident_id, ip=client_ip(request), detail=fields)
    return db.get_incident(incident_id)


@router.post("/{incident_id}/respond")
def respond(
    incident_id: str,
    body: ResponseActionRequest,
    request: Request,
    _payload: dict = Depends(require_privilege_at_least("SECURITY_ENGINEER")),
) -> dict:
    inc = db.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if body.action not in ACTION_LABELS:
        raise HTTPException(status_code=400, detail=f"Unknown action. Valid: {', '.join(sorted(ACTION_LABELS))}")
    actor = f"{_payload['sub']}({_payload['role']})"
    result = response_engine.execute(body.action, incident_id, body.reason, actor)
    return result


@router.get("/{incident_id}/actions")
def incident_actions(incident_id: str, _payload: dict = Depends(current_user)) -> dict:
    all_actions = db.list_response_actions(limit=200)
    items = []
    for a in all_actions:
        if a.get("incident_id") != incident_id:
            continue
        detail = a.get("detail") or {}
        items.append({
            **a,
            "created_at": a.get("ts"),
            "requested_by": detail.get("requested_by") or a.get("actor"),
            "approved_by": detail.get("approved_by"),
            "executed_at": detail.get("executed_at") or (a.get("ts") if a.get("result") == "SUCCESS" else None),
            "dry_run": a.get("result") == "DRY_RUN",
        })
    return {"items": items}


@router.get("/policies/available")
def available_actions(_payload: dict = Depends(current_user)) -> dict:
    out = {}
    for action in sorted(ACTION_LABELS):
        status = response_engine.policy_status(action)
        out[action] = {"label": ACTION_LABELS[action], **status}
    return {"actions": out}
