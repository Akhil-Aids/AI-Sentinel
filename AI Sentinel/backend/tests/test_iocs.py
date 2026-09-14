"""Tests for IOC management: CRUD API, import/export, and ingest matching."""
import time

import pytest

from app import db
from app.services.ioc import ioc_service


def _wait_for_alert(timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        alerts = [a for a in db.list_alerts(limit=50) if a.get("source", "").startswith("ioc:")]
        if alerts:
            return alerts
        time.sleep(0.5)
    return []


@pytest.fixture(scope="module")
def clean_iocs():
    for ioc in db.list_iocs(limit=100000):
        db.delete_ioc(ioc["ioc_id"])
    ioc_service._refresh_cache(force=True)
    yield
    for ioc in db.list_iocs(limit=100000):
        db.delete_ioc(ioc["ioc_id"])
    ioc_service._refresh_cache(force=True)


def test_ioc_crud_roundtrip(client, admin_headers, clean_iocs):
    r = client.post("/api/iocs/", headers=admin_headers, json={
        "ioc_type": "ip", "ioc_value": "203.0.113.77", "verdict": "malicious",
        "confidence": 0.95, "source": "manual", "tags": ["apt"],
    })
    assert r.status_code == 200, r.text
    ioc = r.json()
    assert ioc["ioc_id"].startswith("ioc_")
    assert ioc["verdict"] == "malicious"

    # GET single
    r = client.get(f"/api/iocs/{ioc['ioc_id']}", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["ioc_value"] == "203.0.113.77"

    # List
    r = client.get("/api/iocs/", headers=admin_headers)
    assert r.status_code == 200
    assert len(r.json()["items"]) == 1

    # Update
    r = client.put(f"/api/iocs/{ioc['ioc_id']}", headers=admin_headers, json={
        "ioc_type": "ip", "ioc_value": "203.0.113.77", "verdict": "suspicious",
        "confidence": 0.4, "source": "analyst",
    })
    assert r.status_code == 200
    assert r.json()["verdict"] == "suspicious"

    # Delete requires ADMIN
    r = client.delete(f"/api/iocs/{ioc['ioc_id']}", headers=admin_headers)
    assert r.status_code == 200
    assert client.get(f"/api/iocs/{ioc['ioc_id']}", headers=admin_headers).status_code == 404


def test_ioc_validation(client, admin_headers, clean_iocs):
    r = client.post("/api/iocs/", headers=admin_headers, json={
        "ioc_type": "bogus", "ioc_value": "x", "verdict": "malicious",
    })
    assert r.status_code == 400
    r = client.post("/api/iocs/", headers=admin_headers, json={
        "ioc_type": "ip", "ioc_value": "1.1.1.1", "verdict": "definitely-mean",
    })
    assert r.status_code == 400


def test_ioc_import_json(client, admin_headers, clean_iocs):
    items = [
        {"ioc_type": "domain", "ioc_value": "evil.example.com", "verdict": "malicious",
         "confidence": 0.9, "source": "feed", "tags": ["phishing"]},
        {"ioc_type": "sha256", "ioc_value": "a" * 64, "verdict": "malicious", "confidence": 1.0},
        {"ioc_type": "nope", "ioc_value": "bad", "verdict": "malicious"},
    ]
    r = client.post("/api/iocs/import", headers=admin_headers, json={"items": items})
    assert r.status_code == 200
    body = r.json()
    assert body["inserted"] == 2
    assert body["rejected"] == 1

    # Replace mode clears and re-imports
    r = client.post("/api/iocs/import", headers=admin_headers, json={
        "items": [{"ioc_type": "ip", "ioc_value": "198.51.100.9", "verdict": "malicious"}],
        "mode": "replace",
    })
    assert r.status_code == 200
    assert body["inserted"] >= 0
    r = client.get("/api/iocs/", headers=admin_headers)
    assert len(r.json()["items"]) == 1


def test_ioc_export_csv(client, admin_headers, clean_iocs):
    client.post("/api/iocs/", headers=admin_headers, json={
        "ioc_type": "ip", "ioc_value": "198.51.100.42", "verdict": "malicious",
        "confidence": 0.8, "source": "manual", "tags": ["apt"],
    })
    r = client.get("/api/iocs/export?format=csv", headers=admin_headers)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert "198.51.100.42" in r.text
    assert r.text.splitlines()[0].startswith("ioc_type")


def test_ioc_ingest_match_raises_alert(client, admin_headers, clean_iocs):
    client.post("/api/iocs/", headers=admin_headers, json={
        "ioc_type": "ip", "ioc_value": "198.51.100.66", "verdict": "malicious",
        "confidence": 0.9, "source": "manual",
    })
    # Ingest an event referencing the IOC via source_ip.
    r = client.post("/api/events/ingest", headers=admin_headers, json={
        "events": [
            {"event_type": "auth.failed", "source_ip": "198.51.100.66", "username": "bob",
             "host": "web-01", "severity": "low", "ts": "2026-09-14T10:00:00+00:00"},
        ],
    })
    assert r.status_code == 200, r.text
    assert r.json()["accepted"] == 1

    # The match should have created an alert sourced from ioc:<id>.
    from app.services.ioc import ioc_service
    ioc = ioc_service.lookup("ip", "198.51.100.66")
    alerts = _wait_for_alert()
    assert alerts, "expected an IOC-driven alert"
    assert any(ioc["ioc_id"] in a["source"] for a in alerts)
    assert db.ioc_match_counts(ioc["ioc_id"])["count"] >= 1


def test_ioc_match_recorded_without_autodetect(clean_iocs):
    """A suspicious IOC does not auto-raise an alert but still records the match."""
    db.save_ioc({"ioc_type": "ip", "ioc_value": "203.0.113.200", "verdict": "suspicious",
                 "confidence": 0.5, "source": "analyst"})
    ioc_service._refresh_cache(force=True)
    matches = ioc_service.match_event({
        "event_id": "evt_ioc_test", "event_type": "net.connection",
        "source_ip": "203.0.113.200",
    })
    assert len(matches) == 1
    assert matches[0]["verdict"] == "suspicious"
    assert db.ioc_match_counts(matches[0]["ioc_id"])["count"] >= 1
    ioc_alerts = [a for a in db.list_alerts(limit=50)
                  if a.get("source") == f"ioc:{matches[0]['ioc_id']}"]
    assert not ioc_alerts