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


@router.get("/")
def list_alerts(
    limit: int = Query(100, ge=1, le=500),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    _payload: dict = Depends(current_user),
) -> dict:
    return {"items": db.list_alerts(limit=limit, severity=severity, status=status)}


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
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="alert.update",
                 target=alert_id, ip=client_ip(request), detail=fields)
    return db.get_alert(alert_id)
