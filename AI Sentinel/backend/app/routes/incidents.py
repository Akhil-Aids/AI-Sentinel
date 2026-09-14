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
    assigned_to: Optional[str] = None
    note: Optional[str] = None


class IncidentNote(BaseModel):
    note: str


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
    from app.services import sla as sla_service
    items = sla_service.sla_for_incidents(db.list_incidents(limit=limit, status=status, severity=severity))
    return {"items": items}


@router.get("/{incident_id}")
def incident_detail(incident_id: str, _payload: dict = Depends(current_user)) -> dict:
    from app.services import sla as sla_service
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
    inc["sla"] = sla_service.compute_sla(inc)
    inc["evidence_items"] = db.list_evidence(incident_id=incident_id)
    inc["tasks"] = db.list_tasks(incident_id=incident_id)
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
    if body.assigned_to is not None:
        fields["assigned_to"] = body.assigned_to
    db.update_incident(incident_id, **fields)

    if "status" in fields and fields["status"] != inc.get("status"):
        db.add_incident_history(incident_id, "status", inc.get("status", ""),
                                fields["status"], actor=_payload["sub"], note=body.note or "")
    if "assigned_to" in fields and fields["assigned_to"] != inc.get("assigned_to", ""):
        db.add_incident_history(incident_id, "assigned", "", fields["assigned_to"],
                                actor=_payload["sub"], note=body.note or "")
    if body.analyst_notes is not None and body.analyst_notes != inc.get("analyst_notes", ""):
        db.add_incident_history(incident_id, "notes", "", "", actor=_payload["sub"],
                                note=body.analyst_notes)
    if body.note:
        db.add_notes("incident", incident_id, body.note, author=_payload["sub"])
        db.add_incident_history(incident_id, "note", "", "", actor=_payload["sub"], note=body.note)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="incident.update",
                 target=incident_id, ip=client_ip(request), detail=fields)
    return db.get_incident(incident_id)


@router.get("/{incident_id}/history")
def incident_history(incident_id: str, _payload: dict = Depends(current_user)) -> dict:
    inc = db.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"items": db.list_incident_history(incident_id),
            "notes": db.list_notes("incident", incident_id)}


@router.post("/{incident_id}/notes")
def add_incident_note(incident_id: str, body: IncidentNote, request: Request,
                      _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    inc = db.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if not body.note.strip():
        raise HTTPException(status_code=400, detail="Note cannot be empty")
    note = db.add_notes("incident", incident_id, body.note.strip(), author=_payload["sub"])
    db.add_incident_history(incident_id, "note", "", "", actor=_payload["sub"], note=body.note.strip())
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="incident.note",
                 target=incident_id, ip=client_ip(request))
    return note


@router.get("/{incident_id}/related")
def related_objects(incident_id: str, _payload: dict = Depends(current_user)) -> dict:
    """Find objects related to the incident by shared entity (host/user/IP)."""
    inc = db.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    host, user, src = inc.get("affected_host", ""), inc.get("affected_user", ""), inc.get("source_ip", "")
    clauses, params = ["incident_id != ?"], [incident_id]
    or_clauses = []
    if host:
        or_clauses.append("affected_host = ?")
        params.append(host)
    if user:
        or_clauses.append("affected_user = ?")
        params.append(user)
    if src:
        or_clauses.append("source_ip = ?")
        params.append(src)
    related = []
    if or_clauses:
        related = db._fetch_all(
            f"SELECT incident_id, title, severity, status, risk_score, category, created_at "
            f"FROM incidents WHERE {' AND '.join(clauses + ['(' + ' OR '.join(or_clauses) + ')'])} "
            f"ORDER BY created_at DESC LIMIT 20", tuple(params))

    # Events on the same host/user.
    event_clauses, event_params = ["1=1"], []
    if host:
        event_clauses.append("host = ?")
        event_params.append(host)
    if user:
        event_clauses.append("username = ?")
        event_params.append(user)
    if src:
        event_clauses.append("source_ip = ?")
        event_params.append(src)
    events = db._fetch_all(
        f"SELECT event_id, ts, event_type, severity, host, username, source_ip, dest_ip "
        f"FROM events WHERE {' AND '.join(event_clauses)} ORDER BY ts DESC LIMIT 20",
        tuple(event_params))

    # Managed IOCs referenced by this incident's IPs.
    iocs = db._fetch_all("SELECT * FROM iocs WHERE ioc_value IN (?,?) LIMIT 50",
                         (inc.get("source_ip", ""), inc.get("dest_ip", ""))) if inc.get("source_ip") or inc.get("dest_ip") else []

    return {"incidents": related, "events": events, "iocs": iocs,
            "by": {"host": host or None, "user": user or None, "source_ip": src or None}}


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
