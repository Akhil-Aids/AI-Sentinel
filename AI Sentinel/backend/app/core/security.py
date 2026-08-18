"""Security primitives: password hashing and expiring signed tokens.

Passwords: PBKDF2-HMAC-SHA256 (stdlib, no extra dependencies).
Tokens: signed JSON payload (HMAC-SHA256) with `sub`, `role`, `exp` claims.
No external JWT library required and no secrets leak to the client.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings

bearer_scheme = HTTPBearer(auto_error=False)

# Supported roles, highest privilege first.
ROLES = ("ADMIN", "SOC_ANALYST", "SECURITY_ENGINEER", "VIEWER")

# --------------------------------------------------------------------------- #
# Password hashing
# --------------------------------------------------------------------------- #
_PBKDF2_ITERATIONS = 210_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return "$pbkdf2-sha256${}${}${}$".format(
        _PBKDF2_ITERATIONS,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        parts = stored.split("$")
        if len(parts) != 6 or parts[1] != "pbkdf2-sha256":
            return False
        iterations = int(parts[2])
        salt = base64.urlsafe_b64decode(parts[3])
        expected = base64.urlsafe_b64decode(parts[4])
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Token signing / verification
# --------------------------------------------------------------------------- #
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _sign(message: str) -> str:
    return hmac.new(settings.AUTH_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_token(username: str, role: str, ttl_seconds: Optional[int] = None) -> str:
    if role not in ROLES:
        raise ValueError(f"Unknown role: {role}")
    ttl = ttl_seconds or settings.TOKEN_TTL_SECONDS
    now = int(time.time())
    payload = {"sub": username, "role": role, "iat": now, "exp": now + ttl, "jti": secrets.token_hex(8)}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _sign(body)
    return f"{body}.{sig}"


def decode_token(token: str) -> dict:
    if "." not in token:
        raise HTTPException(status_code=401, detail="Invalid token")
    body, sig = token.split(".", 1)
    if not hmac.compare_digest(sig, _sign(body)):
        raise HTTPException(status_code=401, detail="Invalid token signature")
    try:
        payload = json.loads(_b64d(body).decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed token")
    if int(payload.get("exp", 0)) < int(time.time()):
        raise HTTPException(status_code=401, detail="Token expired")
    if not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Missing subject")
    return payload


def verify_token(credentials: Optional[HTTPAuthorizationCredentials]) -> dict:
    """Return the token payload for a valid bearer token."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing auth token")
    return decode_token(credentials.credentials)


def generate_secret(length: int = 48) -> str:
    return secrets.token_urlsafe(length)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
