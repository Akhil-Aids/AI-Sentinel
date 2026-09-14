"""Tests for threat hunting: query execution, named patterns, CSV export, saved hunts."""
from datetime import datetime, timedelta, timezone

import pytest

from app import db
from app.pipeline.normalize import normalize_raw
from app.services.hunts import PATTERNS, filters_to_csv, run_hunt


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _ts(minutes_ago):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


@pytest.fixture(scope="module")
def seeded_events():
    events = [
        {"ts": _ts(5), "event_type": "auth.failed_login", "source_ip": "10.9.9.9",
         "username": "hunt_u1"},
        {"ts": _ts(4), "event_type": "auth.failed_login", "source_ip": "10.9.9.9",
         "username": "hunt_u2"},
        {"ts": _ts(3), "event_type": "auth.failed_login", "source_ip": "10.9.9.9",
         "username": "hunt_u3"},
        {"ts": _ts(2), "event_type": "net.connection", "source_ip": "10.1.1.1",
         "dest_ip": "198.51.100.10", "port": 443},
        {"ts": _ts(1), "event_type": "phishing.detected", "source_ip": "10.2.2.2",
         "details": {"url": "https://evil.example.com/x"}},
        {"ts": _ts(60 * 30), "event_type": "auth.failed_login", "source_ip": "10.9.9.1",
         "username": "hunt_old"},
    ]
    saved = []
    for ev in events:
        saved.append(db.save_event(normalize_raw(ev, source="hunt-test")))
    yield saved
    db._execute("DELETE FROM events WHERE source = 'hunt-test'")


def test_run_hunt_raw_results(seeded_events):
    result = run_hunt({"event_types": ["auth.failed_login"], "minutes": 60})
    assert result["status"] == "OK"
    assert result["grouped"] is False
    assert result["count"] >= 3
    assert any(r["username"] == "hunt_u1" for r in result["results"])


def test_run_hunt_grouped(seeded_events):
    result = run_hunt({"event_types": ["auth.failed_login"], "minutes": 60,
                       "group_by": "source_ip", "min_group_count": 3})
    assert result["status"] == "OK"
    assert result["grouped"] is True
    top = result["results"][0]
    assert top["key"] == "10.9.9.9"
    assert top["events"] >= 3


def test_run_hunt_named_pattern_applies(seeded_events):
    filters = dict(PATTERNS["brute_force"]["filters"])
    # Seeded data has 3 failed logins; lower the threshold to exercise the recipe.
    filters["min_group_count"] = 2
    result = run_hunt({**filters, "minutes": 60})
    assert result["status"] == "OK"
    assert any(r["key"] == "10.9.9.9" for r in result["results"])


def test_run_hunt_no_match_honest(seeded_events):
    result = run_hunt({"source_ip": "198.51.100.250", "minutes": 60})
    assert result["status"] == "NO_MATCHES"
    assert result["count"] == 0


def test_run_hunt_invalid_filter(seeded_events):
    result = run_hunt({"nonsense_column": "x"})
    assert result["status"] == "ERROR"
    assert result["errors"]


def test_run_hunt_window_respected(seeded_events):
    # hunt_old event is 30 minutes back; a 10 minute window excludes it.
    result = run_hunt({"event_types": ["auth.failed_login"], "minutes": 10})
    assert result["count"] >= 3
    usernames = {r["username"] for r in result["results"]}
    assert "hunt_old" not in usernames


def test_filters_to_csv(seeded_events):
    csv_text = filters_to_csv({"event_types": ["auth.failed_login"], "minutes": 60})
    assert "event_id,ts,event_type" in csv_text.splitlines()[0]
    assert len(csv_text.splitlines()) >= 4


def test_hunt_save_and_run_via_api(client, admin_headers, seeded_events):
    r = client.post("/api/hunts/", headers=admin_headers, json={
        "name": "Hunt test", "description": "d", "filters": {"event_types": ["net.connection"]},
    })
    assert r.status_code == 200, r.text
    hunt = r.json()
    assert hunt["hunt_id"].startswith("hunt_")

    r = client.post(f"/api/hunts/{hunt['hunt_id']}/run", headers=admin_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "OK"
    assert body["count"] >= 1

    r = client.get(f"/api/hunts/{hunt['hunt_id']}/history", headers=admin_headers)
    assert r.status_code == 200
    assert len(r.json()["items"]) == 1

    r = client.delete(f"/api/hunts/{hunt['hunt_id']}", headers=admin_headers)
    assert r.status_code == 200


def test_hunt_patterns_api(client, admin_headers):
    r = client.get("/api/hunts/patterns", headers=admin_headers)
    assert r.status_code == 200
    keys = {p["key"] for p in r.json()["items"]}
    assert "brute_force" in keys and "impossible_travel" in keys


def test_hunt_export_csv(client, admin_headers, seeded_events):
    r = client.get("/api/hunts/export?event_type=auth.failed_login&minutes=60",
                   headers=admin_headers)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert "hunt_u1" in r.text