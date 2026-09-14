"""Alert routes with analyst feedback (true/false positive management)."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from app import db
from app.core.deps import client_ip, current_user, require_privilege_at_least

router = APIRouter()

VALID_ALERT_STATUSES = {"NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    feedback: Optional[str] = None
    note: Optional[str] = None


class AlertNote(BaseModel):
    note: str


@router.get("/")
def list_alerts(
    limit: int = Query(100, ge=1, le=500),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    _payload: dict = Depends(current_user),
) -> dict:
    return {"items": db.list_alerts(limit=limit, severity=severity, status=status)}


@router.get("/{alert_id}")
def get_alert(
    alert_id: str,
    _payload: dict = Depends(current_user),
) -> dict:
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}")
def update_alert(
    alert_id: str,
    body: AlertUpdate,
    request: Request,
    _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST")),
) -> dict:
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    fields = {}
    if body.status:
        if body.status not in VALID_ALERT_STATUSES:
            raise HTTPException(status_code=400,
                                detail=f"Invalid status. Use one of {', '.join(sorted(VALID_ALERT_STATUSES))}")
        fields["status"] = body.status
    if body.assigned_to is not None:
        fields["assigned_to"] = body.assigned_to
    if body.feedback:
        if body.feedback not in ("TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN", "NEEDS_INVESTIGATION"):
            raise HTTPException(status_code=400, detail="Invalid feedback value")
        fields["feedback"] = body.feedback
    db.update_alert(alert_id, **fields)

    # Immutable lifecycle trail: status transitions, assignments, and feedback.
    if "status" in fields and fields["status"] != alert.get("status"):
        db.add_alert_history(alert_id, "status", alert.get("status", ""), fields["status"],
                             actor=_payload["sub"], note=body.note or "")
    if "assigned_to" in fields and fields["assigned_to"] != alert.get("assigned_to", ""):
        db.add_alert_history(alert_id, "assigned", "", fields["assigned_to"],
                             actor=_payload["sub"], note=body.note or "")
    if "feedback" in fields and fields["feedback"] != alert.get("feedback", ""):
        db.add_alert_history(alert_id, "feedback", alert.get("feedback", ""), fields["feedback"],
                             actor=_payload["sub"], note=body.note or "")
    if body.note:
        db.add_notes("alert", alert_id, body.note, author=_payload["sub"])
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="alert.update",
                 target=alert_id, ip=client_ip(request), detail=fields)
    return db.get_alert(alert_id)


@router.get("/{alert_id}/history")
def alert_history(alert_id: str, _payload: dict = Depends(current_user)) -> dict:
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"items": db.list_alert_history(alert_id),
            "notes": db.list_notes("alert", alert_id)}


@router.post("/{alert_id}/notes")
def add_alert_note(alert_id: str, body: AlertNote, request: Request,
                   _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if not body.note.strip():
        raise HTTPException(status_code=400, detail="Note cannot be empty")
    note = db.add_notes("alert", alert_id, body.note.strip(), author=_payload["sub"])
    db.add_alert_history(alert_id, "note", "", "", actor=_payload["sub"], note=body.note.strip())
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="alert.note",
                 target=alert_id, ip=client_ip(request))
    return note
