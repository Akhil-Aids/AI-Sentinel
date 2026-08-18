"""Authentication routes: login, current user, password change, user management.

Default credentials are never hard-coded. The bootstrap administrator account
is created on first startup with a password from SENTINEL_ADMIN_PASSWORD or a
generated random value (written to bootstrap_admin.txt in the backend folder).
"""
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app import db
from app.core.deps import client_ip, current_user, require_privilege_at_least
from app.core.security import (ROLES, hash_password, issue_token, verify_password)

router = APIRouter()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=256)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=256)
    role: str
    full_name: str = ""


class UserUpdateRequest(BaseModel):
    role: str | None = None
    full_name: str | None = None
    is_active: bool | None = None
    password: str | None = None


def _rate_limit_failed(client: str) -> None:
    """Simple in-memory rate limiting for login attempts."""
    import time as _t
    key = f"login_{client}"
    now = _t.monotonic()
    _LOGIN_WINDOWS[key] = [t for t in _LOGIN_WINDOWS.get(key, []) if now - t < 300]
    if len(_LOGIN_WINDOWS[key]) >= 10:
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    _LOGIN_WINDOWS[key].append(now)


_LOGIN_WINDOWS: dict[str, list[float]] = {}


@router.post("/login")
def login(payload: LoginRequest, request: Request) -> dict:
    ip = client_ip(request)
    _rate_limit_failed(ip)
    user = db.get_user_by_username(payload.username.strip())
    if user is None or not verify_password(payload.password, user["password_hash"]):
        db.log_audit(actor=payload.username, action="auth.login", result="FAILED", ip=ip,
                     detail={"reason": "invalid credentials"})
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("is_active", 1):
        db.log_audit(actor=payload.username, action="auth.login", result="BLOCKED", ip=ip,
                     detail={"reason": "account disabled"})
        raise HTTPException(status_code=403, detail="Account disabled")
    db.update_user(user["id"], last_login_at=db._now())
    token = issue_token(user["username"], user["role"])
    db.log_audit(actor=user["username"], role=user["role"], action="auth.login", result="SUCCESS", ip=ip)
    return {
        "token": token,
        "role": user["role"],
        "username": user["username"],
        "expires_in": settings_token_ttl(),
    }


def settings_token_ttl():
    from app.core.config import settings
    return settings.TOKEN_TTL_SECONDS


@router.get("/me")
def me(payload: dict = Depends(current_user)) -> dict:
    user = db.get_user_by_username(payload["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": user["username"], "role": user["role"], "full_name": user["full_name"],
            "is_active": user["is_active"], "created_at": user["created_at"]}


@router.post("/change-password")
def change_password(body: ChangePasswordRequest, request: Request,
                    payload: dict = Depends(current_user)) -> dict:
    user = db.get_user_by_username(payload["sub"])
    if not user or not verify_password(body.current_password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    db.update_user(user["id"], password_hash=hash_password(body.new_password))
    db.log_audit(actor=user["username"], role=user["role"], action="auth.change_password",
                 result="SUCCESS", ip=client_ip(request))
    return {"status": "ok"}


@router.get("/users")
def list_users(payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    return {"items": db.list_users()}


@router.post("/users")
def create_user(body: UserCreateRequest, request: Request,
                payload: dict = Depends(require_privilege_at_least("ADMIN"))) -> dict:
    if body.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of {', '.join(ROLES)}")
    if db.get_user_by_username(body.username):
        raise HTTPException(status_code=409, detail="Username already exists")
    user = db.create_user(body.username, hash_password(body.password), body.role, body.full_name)
    db.log_audit(actor=payload["sub"], role=payload["role"], action="auth.create_user",
                 target=body.username, ip=client_ip(request), detail={"role": body.role})
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserUpdateRequest, request: Request,
                payload: dict = Depends(require_privilege_at_least("ADMIN"))) -> dict:
    existing = db.get_user_by_id(user_id)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
    fields = {}
    if body.role is not None:
        if body.role not in ROLES:
            raise HTTPException(status_code=400, detail="Invalid role")
        fields["role"] = body.role
    if body.full_name is not None:
        fields["full_name"] = body.full_name
    if body.is_active is not None:
        fields["is_active"] = int(body.is_active)
    if body.password:
        fields["password_hash"] = hash_password(body.password)
    db.update_user(user_id, **fields)
    db.log_audit(actor=payload["sub"], role=payload["role"], action="auth.update_user",
                 target=existing["username"], ip=client_ip(request), detail={k: v for k, v in fields.items() if k != "password_hash"})
    return {"status": "ok"}
