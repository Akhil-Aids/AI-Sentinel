"""Observability tests: request-id correlation, structured errors, metric history."""
from fastapi.testclient import TestClient

from app import db
from app.main import app


def test_request_id_header_echoed(client, admin_headers):
    r = client.get("/api/overview", headers={**admin_headers, "X-Request-Id": "corr-123"})
    assert r.status_code == 200
    assert r.headers.get("x-request-id") == "corr-123"


def test_generated_request_id_on_error(client, admin_headers):
    r = client.get("/api/alerts/does-not-exist-xyz", headers=admin_headers)
    assert r.status_code == 404
    body = r.json()
    assert body["detail"] == "Alert not found"
    assert body.get("request_id")
    assert body.get("timestamp")
    # Echoed on the response headers too.
    assert r.headers.get("x-request-id") == body["request_id"]


def test_validation_error_structured(client, admin_headers):
    r = client.post("/api/iocs/", headers=admin_headers, json={})
    assert r.status_code == 422
    body = r.json()
    assert body["request_id"]
    assert isinstance(body["detail"], list)


def test_metric_history_recorded(client):
    db.record_metric("mtta", 12.5, {"label": "MTTA", "samples": 3})
    found = [m for m in db.list_metrics("mtta", limit=50) if m["value"] == 12.5]
    assert found, "recorded metric not persisted"
    latest = db.latest_metric("mtta")
    assert latest is not None
    assert latest["metric_name"] == "mtta"