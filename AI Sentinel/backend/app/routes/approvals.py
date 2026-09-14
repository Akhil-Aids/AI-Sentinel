"""Response approval routes: list/view approvals, approve, deny.

Controls the two-person rule for destructive response actions against
high-severity incidents. Approval records are immutable: a resolved approval
cannot be re-opened.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from app import db
from app.core.deps import client_ip, current_user, require_privilege_at_least
from app.response import response_engine

router = APIRouter()

APPROVAL_FIELDS = {"action": "action", "status": "status", "assigned_to": "assigned_to"}


class ApprovalDecision(BaseModel):
    reason: str = ""


@router.get("/")
def list_approvals(
    status: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    _payload: dict = Depends(current_user),
) -> dict:
    if status and status not in ("PENDING", "APPROVED", "DENIED"):
        raise HTTPException(status_code=400, detail="status must be PENDING, APPROVED or DENIED")
    items = db.list_approvals(limit=limit, status=status)
    # Enrich with incident titles.
    for a in items:
        if a.get("incident_id"):
            inc = db.get_incident(a["incident_id"])
            a["incident_title"] = inc.get("title", "") if inc else ""
    return {"items": items}


@router.get("/{approval_id}")
def get_approval(approval_id: str, _payload: dict = Depends(current_user)) -> dict:
    approval = db.get_approval(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
    inc = db.get_incident(approval.get("incident_id", "")) if approval.get("incident_id") else None
    approval["incident_title"] = inc.get("title", "") if inc else ""
    return approval


@router.post("/{approval_id}/approve")
def approve(approval_id: str, body: ApprovalDecision, request: Request,
            _payload: dict = Depends(require_privilege_at_least("SECURITY_ENGINEER"))) -> dict:
    approval = db.get_approval(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval["status"] != "PENDING":
        raise HTTPException(status_code=409, detail=f"Approval already resolved as {approval['status']}")
    params = approval.get("action_params", {})
    db.resolve_approval(approval_id, "APPROVED", _payload["sub"], body.reason)
    result = response_engine.execute(
        action=approval["action_type"],
        incident_id=params.get("incident_id", approval.get("incident_id", "")),
        reason=params.get("reason", "") or body.reason,
        actor=approval.get("requested_by", "unknown"),
        policy=params.get("policy", approval["action_type"]),
        approval={"approval_id": approval_id, "approved_by": _payload["sub"]},
    )
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="approval.approve",
                 target=approval_id, ip=client_ip(request),
                 detail={"action": approval["action_type"], "reason": body.reason,
                         "result": result.get("result")})
    return {"approval": db.get_approval(approval_id), "outcome": result}


@router.post("/{approval_id}/deny")
def deny(approval_id: str, body: ApprovalDecision, request: Request,
         _payload: dict = Depends(require_privilege_at_least("SECURITY_ENGINEER"))) -> dict:
    approval = db.get_approval(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval["status"] != "PENDING":
        raise HTTPException(status_code=409, detail=f"Approval already resolved as {approval['status']}")
    db.resolve_approval(approval_id, "DENIED", _payload["sub"], body.reason)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="approval.deny",
                 target=approval_id, ip=client_ip(request),
                 detail={"action": approval["action_type"], "reason": body.reason})
    return db.get_approval(approval_id)