"""Tests for alert/incident lifecycle: history trail, assignment, notes, related objects."""
from datetime import datetime, timedelta, timezone

import pytest

from app import db

VALID_STATUSES = {"NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"}


@pytest.fixture(autouse=True)
def _cleanup_lifecycle():
    """Remove records created by this module so shared metric samples stay clean."""
    yield
    for table in ("alert_history", "incident_history", "investigation_notes"):
        db._execute(f"DELETE FROM {table}")
    ids = [i["incident_id"] for i in db.list_incidents(limit=500)
           if i.get("title") in ("lifecycle incident", "related incident")]
    for iid in ids:
        db._execute("DELETE FROM incident_events WHERE incident_id = ?", (iid,))
        db._execute("DELETE FROM incidents WHERE incident_id = ?", (iid,))
    db._execute("DELETE FROM alerts WHERE source = 'test' OR title = 'lifecycle alert'")
    db._execute("DELETE FROM events WHERE event_id = 'evt_related_1'")


def _ts(minutes_ago=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


def _seed_alert(client, admin_headers):
    """Create a real alert via the pipeline (full integration) or direct DB."""
    alert = db.save_alert({"title": "lifecycle alert", "severity": "high", "risk_score": 60,
                           "status": "NEW", "source": "test"})
    return alert


def _make_incident():
    return db.save_incident({
        "title": "lifecycle incident", "severity": "high", "status": "NEW",
        "risk_score": 55, "category": "credential-attack",
        "affected_host": "shared-host-01", "affected_user": "shared-user-01",
        "source_ip": "203.0.113.80",
    })


def test_alert_patch_records_history_and_assign(client, admin_headers):
    alert = _seed_alert(client, admin_headers)
    r = client.patch(f"/api/alerts/{alert['alert_id']}", headers=admin_headers,
                     json={"status": "INVESTIGATING", "assigned_to": "analyst-1",
                           "feedback": "TRUE_POSITIVE", "note": "confirmed malicious"})
    assert r.status_code == 200, r.text
    assert r.json()["assigned_to"] == "analyst-1"

    r = client.get(f"/api/alerts/{alert['alert_id']}/history", headers=admin_headers)
    assert r.status_code == 200
    history = r.json()["items"]
    actions = {h["action"] for h in history}
    assert "status" in actions and "assigned" in actions and "feedback" in actions
    assert len(r.json()["notes"]) == 1
    assert r.json()["notes"][0]["note"] == "confirmed malicious"

    # lifecycle trail should not self-collapse on repeated identical patch
    r = client.patch(f"/api/alerts/{alert['alert_id']}", headers=admin_headers,
                     json={"status": "INVESTIGATING"})
    assert r.status_code == 200


def test_alert_note_endpoint(client, admin_headers):
    alert = _seed_alert(client, admin_headers)
    r = client.post(f"/api/alerts/{alert['alert_id']}/notes", headers=admin_headers,
                    json={"note": "add evidence reference"})
    assert r.status_code == 200
    assert r.json()["note"] == "add evidence reference"
    r = client.get(f"/api/alerts/{alert['alert_id']}/history", headers=admin_headers)
    assert len(r.json()["notes"]) == 1


def test_incident_patch_records_history_and_assignment(client, admin_headers):
    inc = _make_incident()
    r = client.patch(f"/api/incidents/{inc['incident_id']}", headers=admin_headers,
                     json={"status": "CONTAINED", "assigned_to": "lead-analyst",
                           "analyst_notes": "contained the host", "note": "note for the record"})
    assert r.status_code == 200, r.text
    assert r.json()["assigned_to"] == "lead-analyst"
    assert r.json()["status"] == "CONTAINED"

    r = client.get(f"/api/incidents/{inc['incident_id']}/history", headers=admin_headers)
    assert r.status_code == 200
    actions = {h["action"] for h in r.json()["items"]}
    assert "status" in actions and "assigned" in actions
    assert any(n["note"] == "note for the record" for n in r.json()["notes"])

    r = client.post(f"/api/incidents/{inc['incident_id']}/notes", headers=admin_headers,
                    json={"note": "follow-up analysis"})
    assert r.status_code == 200


def test_incident_related_objects(client, admin_headers):
    inc1 = _make_incident()
    inc2 = db.save_incident({
        "title": "related incident", "severity": "medium", "status": "INVESTIGATING",
        "risk_score": 30, "category": "web-attack",
        "affected_host": "shared-host-01", "source_ip": "203.0.113.81",
    })
    db.save_event({"event_id": "evt_related_1", "ts": _ts(),
                   "event_type": "net.connection", "host": "shared-host-01",
                   "username": "shared-user-01", "source_ip": "203.0.113.80"})
    r = client.get(f"/api/incidents/{inc1['incident_id']}/related", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert any(i["incident_id"] == inc2["incident_id"] for i in body["incidents"])
    assert any(e["event_id"] == "evt_related_1" for e in body["events"])


def test_incident_detail_attaches_events_and_history(client, admin_headers):
    inc = _make_incident()
    r = client.get(f"/api/incidents/{inc['incident_id']}", headers=admin_headers)
    assert r.status_code == 200
    assert "_events" in r.json()