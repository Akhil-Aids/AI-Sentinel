"""Case management routes.

A case is an investigation container that groups incidents, alerts, evidence,
notes and tasks around one security narrative. Cases are open/investigating/
closed and support post-incident review (detection gap flag + summary).
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app import db
from app.core.deps import client_ip, require_privilege_at_least

router = APIRouter()

CASE_STATUSES = ("OPEN", "INVESTIGATING", "CLOSED")
CASE_SEVERITIES = ("info", "low", "medium", "high", "critical")


class CaseCreateRequest(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = ""
    severity: str = "medium"
    category: str = ""
    assigned_to: str = ""


class CaseUpdateRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    severity: str | None = None
    category: str | None = None
    assigned_to: str | None = None
    resolution: str | None = None
    detection_gap: bool | None = None
    gap_summary: str | None = None


class CaseLinkRequest(BaseModel):
    incident_id: str | None = None
    alert_id: str | None = None


class CaseNoteRequest(BaseModel):
    note: str = Field(min_length=1, max_length=4000)


@router.post("/")
def create_case(body: CaseCreateRequest, request: Request,
                payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    if body.severity not in CASE_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Severity must be one of {', '.join(CASE_SEVERITIES)}")
    case = db.create_case(body.title, body.description, body.severity, body.category,
                          body.assigned_to, payload["sub"])
    db.log_audit(actor=payload["sub"], role=payload["role"], action="case.create",
                 target=case["case_id"], ip=client_ip(request), detail={"severity": body.severity})
    return case


@router.get("/")
def list_cases(status: str | None = None, assigned_to: str | None = None,
               _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    if status and status not in CASE_STATUSES:
        raise HTTPException(status_code=400, detail=f"Status must be one of {', '.join(CASE_STATUSES)}")
    return {"items": db.list_cases(status=status, assigned_to=assigned_to)}


@router.get("/{case_id}")
def get_case(case_id: str, _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    case = db.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    incident_ids = db.case_incident_ids(case_id)
    alert_ids = db.case_alert_ids(case_id)
    return {
        **case,
        "incidents": [i for i in (db.get_incident(x) for x in incident_ids) if i],
        "alerts": [a for a in (db.get_alert(a) for a in alert_ids) if a],
        "evidence": db.list_evidence(case_id=case_id),
        "tasks": db.list_tasks(case_id=case_id),
        "notes": db.case_notes(case_id),
    }


@router.patch("/{case_id}")
def update_case(case_id: str, body: CaseUpdateRequest, request: Request,
                payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    existing = db.get_case(case_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Case not found")
    fields = {}
    if body.title is not None:
        fields["title"] = body.title
    if body.description is not None:
        fields["description"] = body.description
    if body.status is not None:
        if body.status not in CASE_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status")
        fields["status"] = body.status
        if body.status == "CLOSED" and not existing.get("resolved_at"):
            fields["resolved_at"] = db._now()
    if body.severity is not None:
        if body.severity not in CASE_SEVERITIES:
            raise HTTPException(status_code=400, detail="Invalid severity")
        fields["severity"] = body.severity
    if body.category is not None:
        fields["category"] = body.category
    if body.assigned_to is not None:
        fields["assigned_to"] = body.assigned_to
    if body.resolution is not None:
        fields["resolution"] = body.resolution
    if body.detection_gap is not None:
        fields["detection_gap"] = int(body.detection_gap)
    if body.gap_summary is not None:
        fields["gap_summary"] = body.gap_summary
    db.update_case(case_id, **fields)
    db.log_audit(actor=payload["sub"], role=payload["role"], action="case.update",
                 target=case_id, ip=client_ip(request), detail={k: v for k, v in fields.items()})
    return db.get_case(case_id)


@router.post("/{case_id}/links")
def link_entity(case_id: str, body: CaseLinkRequest, request: Request,
                payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    existing = db.get_case(case_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Case not found")
    linked = {"incident": False, "alert": False}
    if body.incident_id:
        if not db.get_incident(body.incident_id):
            raise HTTPException(status_code=404, detail="Incident not found")
        linked["incident"] = db.case_link_incident(case_id, body.incident_id)
    if body.alert_id:
        if not db.get_alert(body.alert_id):
            raise HTTPException(status_code=404, detail="Alert not found")
        linked["alert"] = db.case_link_alert(case_id, body.alert_id)
    if not body.incident_id and not body.alert_id:
        raise HTTPException(status_code=400, detail="Provide incident_id or alert_id")
    db.log_audit(actor=payload["sub"], role=payload["role"], action="case.link",
                 target=case_id, ip=client_ip(request), detail=linked)
    return {"status": "ok", "linked": linked}


@router.delete("/{case_id}/links/{kind}/{entity_id}")
def unlink_entity(case_id: str, kind: str, entity_id: str, request: Request,
                  payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    if kind == "incident":
        db.case_unlink_incident(case_id, entity_id)
    elif kind == "alert":
        db.case_unlink_alert(case_id, entity_id)
    else:
        raise HTTPException(status_code=400, detail="kind must be incident or alert")
    db.log_audit(actor=payload["sub"], role=payload["role"], action="case.unlink",
                 target=case_id, ip=client_ip(request), detail={"kind": kind, "entity": entity_id})
    return {"status": "ok"}


@router.post("/{case_id}/notes")
def add_case_note(case_id: str, body: CaseNoteRequest, request: Request,
                  payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    note = db.case_add_note(case_id, body.note, payload["sub"])
    db.log_audit(actor=payload["sub"], role=payload["role"], action="case.note",
                 target=case_id, ip=client_ip(request))
    return note


@router.delete("/{case_id}")
def delete_case(case_id: str, request: Request,
                payload: dict = Depends(require_privilege_at_least("SECURITY_ENGINEER"))) -> dict:
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    db.delete_case(case_id)
    db.log_audit(actor=payload["sub"], role=payload["role"], action="case.delete",
                 target=case_id, ip=client_ip(request))
    return {"status": "ok"}