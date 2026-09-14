"""Security posture engine routes: live score, breakdown, history, snapshot."""
from fastapi import APIRouter, Depends, Request

from app import db
from app.core.deps import client_ip, require_privilege_at_least
from app.services import posture

router = APIRouter()


@router.get("/now")
def posture_now(_payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    return posture.compute()


@router.get("/history")
def posture_history(limit: int = 30,
                    _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    return {"items": db.list_posture_history(limit=limit)}


@router.post("/record")
def record_snapshot(request: Request,
                    _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    current = posture.compute()
    snapshot = db.save_posture_snapshot(
        int(round(current["score"])), current["status"],
        {"score": current["score"], "factors": current["factors"],
         "coverage": current["coverage"]})
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="posture.record",
                 target=str(current["status"]), ip=client_ip(request),
                 detail={"score": current["score"]})
    return snapshot