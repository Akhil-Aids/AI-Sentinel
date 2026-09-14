"""API key management for machine/integration access.

Keys are named, scoped, per-role machine credentials that can be rotated and
revoked. The raw secret is returned exactly once at creation.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app import db
from app.core import apikey as apikey_core
from app.core.deps import client_ip, require_privilege_at_least
from app.core.security import ROLES

router = APIRouter()


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=3, max_length=100)
    scope: list[str] = Field(default=["read"])
    role: str = "VIEWER"
    description: str = ""
    expires_in_days: int = Field(default=365, ge=1, le=3650)


class ApiKeyUpdateRequest(BaseModel):
    name: str | None = None
    scope: list[str] | None = None
    role: str | None = None
    description: str | None = None


def _validate_scope(scope: list[str]) -> str:
    unknown = [s for s in scope if s not in apikey_core.DEFAULT_SCOPES]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown scope(s): {', '.join(unknown)}")
    return ",".join(scope)


def _expires_at(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


@router.post("/api-keys")
def create_api_key(body: ApiKeyCreateRequest, request: Request,
                   payload: dict = Depends(require_privilege_at_least("ADMIN"))) -> dict:
    if body.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of {', '.join(ROLES)}")
    key_id = apikey_core.generate_key_id()
    secret = apikey_core.generate_secret()
    record = db.create_api_key(
        key_id=key_id, key_hash=apikey_core.hash_key(key_id, secret),
        name=body.name, scope=_validate_scope(body.scope), role=body.role,
        created_by=payload["sub"], description=body.description,
        expires_at=_expires_at(body.expires_in_days),
    )
    db.log_audit(actor=payload["sub"], role=payload["role"], action="apikey.create",
                 target=key_id, ip=client_ip(request),
                 detail={"name": body.name, "scope": body.scope, "role": body.role,
                         "expires_in_days": body.expires_in_days})
    return {**record, "key": f"{key_id}:{secret}", "note": "Store this secret now; it will not be shown again."}


@router.get("/api-keys")
def list_api_keys(include_revoked: bool = False,
                  _payload: dict = Depends(require_privilege_at_least("ADMIN"))) -> dict:
    return {"items": db.list_api_keys(include_revoked=include_revoked)}


@router.patch("/api-keys/{key_id}")
def update_api_key(key_id: str, body: ApiKeyUpdateRequest, request: Request,
                   payload: dict = Depends(require_privilege_at_least("ADMIN"))) -> dict:
    existing = db.get_api_key_public(key_id)
    if not existing:
        raise HTTPException(status_code=404, detail="API key not found")
    scope = _validate_scope(body.scope) if body.scope is not None else None
    if body.role is not None and body.role not in ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")
    db.update_api_key_meta(key_id, name=body.name, scope=scope, role=body.role, description=body.description)
    db.log_audit(actor=payload["sub"], role=payload["role"], action="apikey.update",
                 target=key_id, ip=client_ip(request))
    return db.get_api_key_public(key_id)


@router.post("/api-keys/{key_id}/rotate")
def rotate_api_key(key_id: str, request: Request,
                   payload: dict = Depends(require_privilege_at_least("ADMIN"))) -> dict:
    existing = db.get_api_key_public(key_id)
    if not existing:
        raise HTTPException(status_code=404, detail="API key not found")
    if existing.get("revoked_at"):
        raise HTTPException(status_code=409, detail="Cannot rotate a revoked key")
    secret = apikey_core.generate_secret()
    db.set_api_key_hash(key_id, apikey_core.hash_key(key_id, secret))
    db.log_audit(actor=payload["sub"], role=payload["role"], action="apikey.rotate",
                 target=key_id, ip=client_ip(request))
    return {**db.get_api_key_public(key_id), "key": f"{key_id}:{secret}",
            "note": "Store this secret now; the previous secret is invalid."}


@router.post("/api-keys/{key_id}/revoke")
def revoke_api_key(key_id: str, request: Request,
                   payload: dict = Depends(require_privilege_at_least("ADMIN"))) -> dict:
    existing = db.get_api_key_public(key_id)
    if not existing:
        raise HTTPException(status_code=404, detail="API key not found")
    if existing.get("revoked_at"):
        raise HTTPException(status_code=409, detail="API key already revoked")
    db.revoke_api_key(key_id)
    db.log_audit(actor=payload["sub"], role=payload["role"], action="apikey.revoke",
                 target=key_id, ip=client_ip(request))
    return {"status": "ok", "key_id": key_id}