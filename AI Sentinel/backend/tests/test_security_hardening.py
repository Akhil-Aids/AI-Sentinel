"""Security hardening tests: prod secret guard, token revocation, RBAC gating,
rate limiting, alert status validation, X-Forwarded-For spoofing."""
import pytest

from app.core.config import settings, validate_settings
from app.core.deps import _user_cache
from conftest import TEST_PASSWORD, TEST_USERNAME


def test_production_secret_guard(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "AUTH_SECRET", "development-only-change-me")
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "ADMIN_PASSWORD", "")
    with pytest.raises(RuntimeError):
        validate_settings()


def test_production_requires_real_secret(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "AUTH_SECRET", "a-real-rotated-secret-value")
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "ADMIN_PASSWORD", "")
    # Should not raise.
    validate_settings()


def test_viewer_cannot_ingest(client):
    # Create a VIEWER user and login.
    viewer_pass = "viewer-pass-123"
    res = client.post("/api/auth/users", json={
        "username": "viewer1", "password": viewer_pass, "role": "VIEWER",
    }, headers={"Authorization": f"Bearer {_admin_token(client)}"})
    assert res.status_code in (200, 409)
    login = client.post("/api/auth/login", json={"username": "viewer1", "password": viewer_pass})
    assert login.status_code == 200, login.text
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # VIEWER may read overview but not write telemetry or analyze phishing.
    assert client.get("/api/overview", headers=headers).status_code == 200
    ingest = client.post("/api/events/ingest", headers=headers,
                         json={"events": [{"event_type": "auth.failed_login"}]})
    assert ingest.status_code == 403
    phish = client.post("/api/phishing/analyze", headers=headers,
                        json={"url": "https://example.com"})
    assert phish.status_code == 403


def _admin_token(client):
    res = client.post("/api/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})
    assert res.status_code == 200
    return res.json()["token"]


def test_token_revocation_on_disable(client):
    admin = _admin_token(client)
    admin_headers = {"Authorization": f"Bearer {admin}"}
    user_pass = "revoked-pass-123"
    res = client.post("/api/auth/users", json={
        "username": "revoke_me", "password": user_pass, "role": "SOC_ANALYST",
    }, headers=admin_headers)
    assert res.status_code == 200, res.text
    login = client.post("/api/auth/login", json={"username": "revoke_me", "password": user_pass})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/overview", headers=headers).status_code == 200

    # Disable the user -> their existing token must stop working immediately.
    uid = res.json()["id"]
    patch = client.patch(f"/api/auth/users/{uid}", json={"is_active": False}, headers=admin_headers)
    assert patch.status_code == 200
    _user_cache.clear()
    assert client.get("/api/overview", headers=headers).status_code == 401


def test_alert_status_validation(client, admin_headers):
    res = client.get("/api/alerts/", headers=admin_headers)
    alerts = res.json()["items"]
    if not alerts:
        pytest.skip("no alerts in test DB")
    aid = alerts[0]["alert_id"]
    bad = client.patch(f"/api/alerts/{aid}", json={"status": "BOGUS"}, headers=admin_headers)
    assert bad.status_code == 400
    ok = client.patch(f"/api/alerts/{aid}", json={"status": "ACKNOWLEDGED"}, headers=admin_headers)
    assert ok.status_code == 200
    assert ok.json()["status"] == "ACKNOWLEDGED"


def test_incident_status_validation(client, admin_headers):
    res = client.get("/api/incidents/", headers=admin_headers)
    incs = res.json()["items"]
    if not incs:
        pytest.skip("no incidents in test DB")
    iid = incs[0]["incident_id"]
    bad = client.patch(f"/api/incidents/{iid}", json={"status": "NOT_A_STATUS"}, headers=admin_headers)
    assert bad.status_code == 400


def test_forwarded_for_header_not_trusted_without_proxy(client):
    # client_ip() must ignore X-Forwarded-For unless it originates from a
    # trusted proxy, so rate limiting / audit cannot be spoofed.
    from app.core.deps import client_ip
    from starlette.requests import Request

    scope = {
        "client": ("1.2.3.4", 54321),
        "headers": [(b"x-forwarded-for", b"evil.example:80")],
        "type": "http",
    }
    req = Request(scope)
    assert client_ip(req) == "1.2.3.4"


def test_batch_limit_enforced(client, admin_headers):
    events = [{"event_type": "info.test"} for _ in range(1001)]
    res = client.post("/api/events/ingest", json={"events": events}, headers=admin_headers)
    assert res.status_code == 400


def test_malformed_event_rejected(client, admin_headers):
    res = client.post("/api/events/ingest", headers=admin_headers,
                      json={"events": [{"event_type": "x" * 5000}]})
    assert res.status_code == 200
    body = res.json()
    assert body["accepted"] == 0
    assert body["rejected"] >= 1
