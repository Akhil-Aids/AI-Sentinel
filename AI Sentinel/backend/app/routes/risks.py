"""User/asset risk insights route: explainable risk scores with factors."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from app import db
from app.core.deps import client_ip, current_user, require_privilege_at_least
from app.services.risk_insights import (compute_asset_risk, compute_user_risk,
                                        recompute_all_assets, recompute_all_users)

router = APIRouter()


class RecomputeRequest(BaseModel):
    entity: str  # 'users' or 'assets'


@router.get("/users")
def list_users(limit: int = Query(100, ge=1, le=500),
               _payload: dict = Depends(current_user)) -> dict:
    return {"items": db.list_user_risk(limit=limit), "order": "risk_score DESC"}


@router.get("/users/{username}")
def user_detail(username: str, _payload: dict = Depends(current_user)) -> dict:
    return compute_user_risk(username)


@router.get("/assets")
def list_assets(limit: int = Query(100, ge=1, le=500),
                _payload: dict = Depends(current_user)) -> dict:
    return {"items": db.list_asset_risk(limit=limit), "order": "risk_score DESC"}


@router.get("/assets/{hostname}")
def asset_detail(hostname: str, _payload: dict = Depends(current_user)) -> dict:
    return compute_asset_risk(hostname)


@router.post("/recompute")
def recompute(body: RecomputeRequest, request: Request,
              _payload: dict = Depends(require_privilege_at_least("ADMIN"))) -> dict:
    if body.entity not in ("users", "assets"):
        raise HTTPException(status_code=400, detail="entity must be 'users' or 'assets'")
    if body.entity == "users":
        count = recompute_all_users()
    else:
        count = recompute_all_assets()
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="risk.recompute",
                 ip=client_ip(request), detail={"entity": body.entity, "count": count})
    return {"status": "ok", "entity": body.entity, "updated": count}