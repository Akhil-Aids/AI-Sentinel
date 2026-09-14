"""API key primitives: format, hashing, header parsing.

Keys are `sk_live_<public id>` shown once at creation; the secret component is
stored only as a salted digest (`hashlib.sha256(key_id + ':' + secret)`), so a
DB leak does not expose usable credentials.
"""
import hashlib
import hmac
import secrets

PREFIX = "sk_live_"
DEFAULT_SCOPES = ("read", "ingest", "respond", "admin")


def generate_key_id() -> str:
    return f"{PREFIX}{secrets.token_hex(8)}"


def generate_secret() -> str:
    return secrets.token_urlsafe(32)


def hash_key(key_id: str, secret: str) -> str:
    return hashlib.sha256(f"{key_id}:{secret}".encode("utf-8")).hexdigest()


def parse_header(header: str) -> tuple[str, str] | None:
    """Split `X-API-Key: <key_id>:<secret>` into its parts."""
    if not header:
        return None
    parts = header.strip().split(":", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    return parts[0], parts[1]


def verify_digest(key_id: str, secret: str, stored_hash: str) -> bool:
    expected = hash_key(key_id, secret)
    return hmac.compare_digest(expected, stored_hash)