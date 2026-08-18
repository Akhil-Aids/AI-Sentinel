"""Unit tests for password hashing and token signing."""
import pytest
from fastapi import HTTPException

from app.core.security import (ROLES, decode_token, hash_password, issue_token, verify_password)


def test_password_roundtrip():
    h = hash_password("correct horse battery staple")
    assert h.startswith("$pbkdf2-sha256$")
    assert verify_password("correct horse battery staple", h) is True


def test_password_wrong_value():
    h = hash_password("right-password")
    assert verify_password("wrong-password", h) is False


def test_password_garbage_hash():
    assert verify_password("anything", "not-a-valid-hash") is False
    assert verify_password("anything", "") is False
    assert verify_password("anything", "$pbkdf2-sha256$1$aa$bb") is False


def test_hashes_are_unique():
    h1 = hash_password("same-password")
    h2 = hash_password("same-password")
    assert h1 != h2
    assert verify_password("same-password", h1) and verify_password("same-password", h2)


def test_token_issue_and_decode():
    token = issue_token("analyst1", "SOC_ANALYST")
    payload = decode_token(token)
    assert payload["sub"] == "analyst1"
    assert payload["role"] == "SOC_ANALYST"
    assert payload["exp"] > 0


def test_token_tampered():
    token = issue_token("admin", "ADMIN")
    body, sig = token.rsplit(".", 1)
    forged = f"{body}X.{sig}"
    with pytest.raises(HTTPException):
        decode_token(forged)


def test_token_missing_signature():
    token = issue_token("admin", "ADMIN")
    body = token.split(".")[0]
    with pytest.raises(HTTPException):
        decode_token(body)


def test_token_unknown_role_rejected():
    with pytest.raises(ValueError):
        issue_token("x", "SUPERUSER")


def test_roles_defined():
    for role in ("ADMIN", "SOC_ANALYST", "SECURITY_ENGINEER", "VIEWER"):
        assert role in ROLES
