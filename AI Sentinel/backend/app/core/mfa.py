"""RFC 6238 TOTP two-factor authentication (stdlib only, no external deps).

Secrets are stored base32-encoded (Google Authenticator / FreeOTP compatible).
Codes are 6 digits, 30-second time step, SHA-1, with a ±1 window tolerance.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

_STEP_SECONDS = 30
_DIGITS = 6
_WINDOW = 1


def generate_secret(bits: int = 160) -> str:
    """Return a base32 secret suitable for TOTP authenticator apps."""
    raw = secrets.token_bytes(bits // 8)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _counter_at(timestamp: int) -> int:
    return max(0, int(timestamp) // _STEP_SECONDS)


def _dynamic_truncate(digest: bytes) -> int:
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return code


def totp_code(secret: str, timestamp: int | None = None) -> str:
    """Compute the current (or given-time) TOTP code for a base32 secret."""
    ts = timestamp if timestamp is not None else int(time.time())
    key = _b32decode(secret)
    msg = struct.pack(">Q", _counter_at(ts))
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    code = _dynamic_truncate(digest) % (10 ** _DIGITS)
    return str(code).zfill(_DIGITS)


def _b32decode(secret: str) -> bytes:
    cleaned = secret.strip().upper().replace(" ", "")
    padding = "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned + padding)


def verify_totp(secret: str, code: str, timestamp: int | None = None) -> bool:
    """Verify a code within the ±window tolerance around the current step."""
    ts = timestamp if timestamp is not None else int(time.time())
    candidate = (code or "").strip()
    if not candidate.isdigit() or len(candidate) != _DIGITS:
        return False
    for offset in range(-_WINDOW, _WINDOW + 1):
        if hmac.compare_digest(totp_code(secret, ts + offset * _STEP_SECONDS), candidate):
            return True
    return False


def provisioning_uri(username: str, secret: str, issuer: str = "AI Sentinel") -> str:
    params = f"secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={_DIGITS}&period={_STEP_SECONDS}"
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?{params}"