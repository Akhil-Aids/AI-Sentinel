"""FastAPI dependencies for authentication and authorization."""
import time
from typing import Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials

from app.core.security import ROLES, verify_token
from app.core.security import bearer_scheme

_ROLE_LEVEL = {role: i for i, role in enumerate(ROLES)}  # ADMIN=0 highest

# Token revocation set (in-memory; survives for the lifetime of the process).
# Tokens are short-lived (TTL-based), so this is bounded.
_revoked_tokens: set[str] = set()

# Short-lived cache: user existence/active flag checked against the DB so
# disabled/deleted users lose access within ~5s (token revocation).
_user_cache: dict[str, tuple[float, bool]] = {}
_USER_CACHE_TTL = 5.0


def _user_is_active(username: str) -> bool:
    from app import db
    now = time.monotonic()
    cached = _user_cache.get(username)
    if cached and now - cached[0] < _USER_CACHE_TTL:
        return cached[1]
    user = db.get_user_by_username(username)
    active = bool(user and user.get("is_active", 1))
    _user_cache[username] = (now, active)
    return active


def current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> dict:
    payload = verify_token(credentials)
    raw_token = credentials.credentials if credentials else ""
    if raw_token and raw_token in _revoked_tokens:
        raise HTTPException(status_code=401, detail="Token has been revoked")
    if not _user_is_active(payload.get("sub", "")):
        raise HTTPException(status_code=401, detail="Account disabled or removed")
    return payload


def require_roles(*roles: str):
    """Dependency factory: restrict access to the given roles."""
    allowed = set(roles)

    def _check(payload: dict = Depends(current_user)) -> dict:
        if payload.get("role") not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return payload

    return _check


def require_privilege_at_least(role: str):
    """Allow access when the user's role is at or above the given role."""
    required_level = _ROLE_LEVEL.get(role, len(ROLES))

    def _check(payload: dict = Depends(current_user)) -> dict:
        level = _ROLE_LEVEL.get(payload.get("role"), len(ROLES))
        if level > required_level:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return payload

    return _check


def client_ip(request: Request) -> str:
    """Derive the client IP, only trusting X-Forwarded-For from known proxies.

    Direct connections are used as-is. This prevents spoofing the rate-limiter
    and audit IP via a user-supplied X-Forwarded-For header.
    """
    from app.core.config import settings
    peer = request.client.host if request.client else ""
    if peer and peer in settings.TRUSTED_PROXIES:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return peer
