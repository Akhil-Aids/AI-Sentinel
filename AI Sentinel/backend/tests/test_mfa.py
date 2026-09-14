"""TOTP MFA: enrollment, challenge, enforcement (provisioning is RFC 6238
compatible with standard authenticator apps)."""
import os

import pytest

from app import db
from app.core import mfa as mfa_core
from app.core.security import hash_password
from app.routes import auth as _auth

# Reset MFA enforcement to a known state for this module.
_from_env = {}


def _make_user(client, username, password, role):
    db.create_user(username, hash_password(password), role)
    res = client.post("/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    return res.json()["token"]


def test_totp_code_generation_and_verification():
    secret = mfa_core.generate_secret()
    assert len(secret) >= 16
    code = mfa_core.totp_code(secret)
    assert len(code) == 6 and code.isdigit()
    assert mfa_core.verify_totp(secret, code)
    assert not mfa_core.verify_totp(secret, "000000")
    assert not mfa_core.verify_totp(secret, "12345")
    # Same code must regenerate within the window.
    assert mfa_core.verify_totp(secret, code)


def test_provisioning_uri_shape():
    uri = mfa_core.provisioning_uri("analyst", "ABCDEFGHIJKLMNOP")
    assert uri.startswith("otpauth://totp/AI%20Sentinel")
    assert "secret=ABCDEFGHIJKLMNOP" in uri
    assert "period=30" in uri


def test_mfa_flow_enroll_confirm_and_login(client):
    username = f"mfa_user_{os.getpid()}"
    password = "mfa-pass-123"
    token = _make_user(client, username, password, "SOC_ANALYST")
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/api/auth/mfa/status", headers=headers).json()["enabled"] is False

    enroll = client.post("/api/auth/mfa/enroll", headers=headers, json={"password": password})
    assert enroll.status_code == 200, enroll.text
    secret = enroll.json()["secret"]
    assert "otpauth_uri" in enroll.json()

    wrong = client.post("/api/auth/mfa/confirm", headers=headers, json={"otp": "000000"})
    assert wrong.status_code == 401

    code = mfa_core.totp_code(secret)
    ok = client.post("/api/auth/mfa/confirm", headers=headers, json={"otp": code})
    assert ok.status_code == 200, ok.text
    assert client.get("/api/auth/mfa/status", headers=headers).json()["enabled"] is True

    # Re-enroll while enabled is rejected.
    dup = client.post("/api/auth/mfa/enroll", headers=headers, json={"password": password})
    assert dup.status_code == 409

    # Login now requires the second factor.
    login = client.post("/api/auth/login", json={"username": username, "password": password})
    assert login.status_code == 200, login.text
    assert login.json()["mfa_required"] is True
    assert login.json()["method"] == "totp"
    partial = login.json()["partial_token"]

    # The partial token must not grant session access.
    part_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {partial}"})
    assert part_res.status_code in (401, 403)

    # Wrong OTP fails.
    bad = client.post("/api/auth/mfa/verify-login",
                      json={"partial_token": partial, "otp": "000000"})
    assert bad.status_code == 401

    good = client.post("/api/auth/mfa/verify-login",
                       json={"partial_token": partial, "otp": mfa_core.totp_code(secret)})
    assert good.status_code == 200, good.text
    assert good.json()["token"]
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {good.json()['token']}"}).status_code == 200


def test_mfa_disable_requires_both_factors(client):
    username = f"mfa_disable_{os.getpid()}"
    password = "mfa-off-123"
    token = _make_user(client, username, password, "VIEWER")
    headers = {"Authorization": f"Bearer {token}"}
    secret = client.post("/api/auth/mfa/enroll", headers=headers, json={"password": password}).json()["secret"]
    client.post("/api/auth/mfa/confirm", headers=headers, json={"otp": mfa_core.totp_code(secret)})

    bad = client.post("/api/auth/mfa/disable", headers=headers, json={"password": "wrong", "otp": mfa_core.totp_code(secret)})
    assert bad.status_code == 401
    bad2 = client.post("/api/auth/mfa/disable", headers=headers, json={"password": password, "otp": "000000"})
    assert bad2.status_code == 401

    ok = client.post("/api/auth/mfa/disable", headers=headers, json={"password": password, "otp": mfa_core.totp_code(secret)})
    assert ok.status_code == 200, ok.text
    status = client.get("/api/auth/mfa/status", headers=headers).json()
    assert status["enabled"] is False


def test_mfa_required_roles_enforced(monkeypatch, client):
    """When a role is in MFA_REQUIRED_ROLES, its members are blocked until MFA."""
    from app.core import deps, config
    monkeypatch.setattr(config.settings, "MFA_REQUIRED_ROLES", ["ADMIN"])
    deps._mfa_cache.clear()

    username = f"mfa_admin_{os.getpid()}"
    password = "mfa-admin-99"
    db.create_user(username, hash_password(password), "ADMIN")
    login = client.post("/api/auth/login", json={"username": username, "password": password})
    assert login.status_code == 200
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {login.json()['token']}"})
    assert res.status_code == 403
    assert "MFA" in res.json()["detail"]

    monkeypatch.setattr(config.settings, "MFA_REQUIRED_ROLES", [])
    deps._mfa_cache.clear()
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {login.json()['token']}"})
    assert res.status_code == 200


def test_admin_can_force_disable_mfa(client, admin_headers):
    username = f"mfa_adminreset_{os.getpid()}"
    password = "reset-pass-1"
    token = _make_user(client, username, password, "SECURITY_ENGINEER")
    headers = {"Authorization": f"Bearer {token}"}
    # Find user id via admin listing.
    users = client.get("/api/auth/users", headers=admin_headers).json()["items"]
    uid = next(u["id"] for u in users if u["username"] == username)
    assert users and any(u["username"] == username for u in users)

    secret = client.post("/api/auth/mfa/enroll", headers=headers, json={"password": password}).json()["secret"]
    client.post("/api/auth/mfa/confirm", headers=headers, json={"otp": mfa_core.totp_code(secret)})

    res = client.patch(f"/api/auth/users/{uid}", headers=admin_headers, json={"mfa_enabled": False})
    assert res.status_code == 200, res.text
    status = client.get("/api/auth/mfa/status", headers=headers).json()
    assert status["enabled"] is False