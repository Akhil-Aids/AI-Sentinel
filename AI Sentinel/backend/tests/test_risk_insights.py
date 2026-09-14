"""Tests for explainable user/asset risk scoring."""
import pytest

from app import db
from app.pipeline.normalize import normalize_raw
from app.services.risk_insights import compute_asset_risk, compute_user_risk, recompute_all_users


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture(scope="module")
def seeded_risk_data():
    db.save_event(normalize_raw({
        "ts": _now(), "event_type": "auth.failed_login", "username": "risk_user_1",
        "host": "risk-asset-01", "severity": "high", "confidence": 0.9,
        "source_ip": "203.0.113.77",
    }, source="risk-test"))
    db.save_event(normalize_raw({
        "ts": _now(), "event_type": "auth.failed_login", "username": "risk_user_1",
        "host": "risk-asset-01", "severity": "critical", "confidence": 0.95,
        "source_ip": "203.0.113.77",
    }, source="risk-test"))
    db.save_incident({
        "title": "risk incident", "severity": "high", "status": "NEW", "risk_score": 80,
        "category": "credential-attack", "affected_host": "risk-asset-01",
        "affected_user": "risk_user_1",
    })
    yield
    db._execute("DELETE FROM events WHERE source = 'risk-test'")


def test_compute_user_risk_explainable(seeded_risk_data):
    row = compute_user_risk("risk_user_1", force=True)
    assert row["username"] == "risk_user_1"
    assert row["risk_score"] >= 30
    assert row["risk_level"] in ("medium", "high", "critical")
    factors = row["risk_factors"]
    assert any(f["factor"] == "high_critical_events" for f in factors)
    assert any(f["factor"] == "open_incidents" for f in factors)
    # Explainability: every factor has an effect and detail.
    for f in factors:
        assert "factor" in f and "effect" in f and "detail" in f


def test_compute_asset_risk_explainable(seeded_risk_data):
    row = compute_asset_risk("risk-asset-01", force=True)
    assert row["hostname"] == "risk-asset-01"
    assert row["risk_score"] >= 30
    factors = row["risk_factors"]
    assert any(f["factor"] == "high_critical_events" for f in factors)
    assert any(f["factor"] == "open_incidents" for f in factors)


def test_unknown_user_low_risk():
    row = compute_user_risk("definitely-not-real-user-xyz", force=True)
    assert row["risk_score"] == 0
    assert row["risk_level"] == "low"


def test_recompute_all_users(seeded_risk_data):
    count = recompute_all_users()
    users = {u["username"] for u in db.list_user_risk(limit=500)}
    assert "risk_user_1" in users
    assert count >= 1


def test_risks_api(client, admin_headers, seeded_risk_data):
    r = client.get("/api/risks/users/risk_user_1", headers=admin_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["username"] == "risk_user_1"
    assert body["risk_factors"]

    r = client.get("/api/risks/assets/risk-asset-01", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["hostname"] == "risk-asset-01"

    r = client.get("/api/risks/users", headers=admin_headers)
    assert r.status_code == 200
    assert any(i["username"] == "risk_user_1" for i in r.json()["items"])

    r = client.post("/api/risks/recompute", headers=admin_headers, json={"entity": "assets"})
    assert r.status_code == 200
    assert r.json()["entity"] == "assets"
    assert r.json()["updated"] >= 1