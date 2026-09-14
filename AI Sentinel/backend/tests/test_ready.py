"""Readiness probe and component-health tests."""
from app import db


def test_ready_probe_returns_200(client):
    res = client.get("/api/ready")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] == "ok"
    assert body["checks"]["pipeline"] in ("ok", "starting")


def test_public_health_has_components(client):
    res = client.get("/api/system/health")
    assert res.status_code == 200
    body = res.json()
    assert "components" in body
    comps = body["components"]
    assert comps["database"]["status"] == "HEALTHY"
    assert comps["pipeline"]["status"] in ("HEALTHY", "STOPPED")
    assert "websocket" in comps and "clients" in comps["websocket"]
    assert comps["threat_intel"]["status"] in ("CONNECTED", "NOT_CONFIGURED")
    assert "ai_provider" in comps
    assert comps["notifications"]["webhook"] in ("CONFIGURED", "NOT_CONFIGURED")


def test_ready_requires_db_tables(client, admin_headers):
    # The readiness check depends on the pipeline as well as the database.
    db.init_schema()
    res = client.get("/api/ready")
    assert res.status_code == 200