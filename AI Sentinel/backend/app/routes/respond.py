"""Response action route — execute controlled defensive responses."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.deps import current_user, require_privilege_at_least
from app.response import response_engine

router = APIRouter()


class RespondRequest(BaseModel):
    incident_id: str
    action: str
    reason: str = ""
    policy: str = ""


@router.post("/")
def respond(body: RespondRequest, payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    """Execute a controlled defensive response action."""
    result = response_engine.execute(
        action=body.action,
        incident_id=body.incident_id,
        reason=body.reason,
        actor=payload.get("sub", "unknown"),
        policy=body.policy,
    )
    if not result.get("executed") and not result.get("dry_run_recorded"):
        raise HTTPException(status_code=400, detail=result.get("reason", "Action not permitted"))
    return result


@router.get("/policies")
def list_policies(_payload: dict = Depends(current_user)) -> dict:
    """List available response policies and their current status."""
    from app.response import POLICIES, ACTION_LABELS
    items = []
    for action, policy in POLICIES.items():
        items.append({
            "action": action,
            "label": ACTION_LABELS.get(action, action),
            "permitted": policy["permitted"],
            "destructive": policy.get("destructive", False),
        })
    return {"items": items}
