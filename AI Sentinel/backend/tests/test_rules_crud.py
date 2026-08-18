"""Detection-rule management: create/update/version history/rollback/delete,
and test-against-history on a live predicate."""
import time

from conftest import TEST_PASSWORD, TEST_USERNAME


def _login(client):
    res = client.post("/api/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})
    assert res.status_code == 200
    return res.json()["token"]


def _wait_for(client, headers, path, predicate, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = client.get(path, headers=headers)
        if res.status_code == 200 and predicate(res.json()):
            return res.json()
        time.sleep(0.5)
    return None


def test_rule_crud_and_rollback(client):
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    # rule_id must map to a known predicate (here the generic count predicate).
    rule_id = "count_events_gt"
    create = client.post("/api/rules/", headers=headers, json={
        "rule_id": rule_id,
        "name": "Custom brute force (test)",
        "description": "Test rule created via API",
        "category": "credential-attack",
        "enabled": True,
        "severity": "high",
        "mitre": ["T1110"],
        "config": {"event_type": "auth.failed_login", "key_field": "source_ip",
                   "window_minutes": 5, "min_count": 5},
    })
    assert create.status_code == 200, create.text
    assert create.json()["version"] == 1

    # Unknown predicate -> 400
    bad = client.post("/api/rules/", headers=headers, json={
        "rule_id": "zzz_not_a_predicate", "name": "bad", "severity": "low",
        "config": {},
    })
    assert bad.status_code == 400

    # Update -> version bump, history grows.
    update = client.put(f"/api/rules/{rule_id}", headers=headers, json={
        "rule_id": rule_id,
        "name": "Custom brute force v2 (test)",
        "description": "Edited via API",
        "category": "credential-attack",
        "enabled": True,
        "severity": "critical",
        "mitre": ["T1110"],
        "config": {"event_type": "auth.failed_login", "key_field": "source_ip",
                   "window_minutes": 5, "min_count": 4},
    })
    assert update.status_code == 200, update.text
    assert update.json()["version"] == 2

    hist = client.get(f"/api/rules/{rule_id}/history", headers=headers).json()
    assert len(hist["items"]) == 2
    assert hist["current_version"] == 2

    # Rollback to v1.
    rollback = client.post(f"/api/rules/{rule_id}/rollback", headers=headers, json={"version": 1})
    assert rollback.status_code == 200, rollback.text
    assert rollback.json()["name"] == "Custom brute force (test)"
    assert rollback.json()["severity"] == "high"
    assert rollback.json()["version"] == 3

    # Test-against-history: fire the campaign, then ask the rule how it would behave.
    events = [
        {"ts": f"2026-08-16T15:0{i}:00+00:00", "event_type": "auth.failed_login",
         "source_ip": "203.0.113.88", "username": f"u{i % 2}"}
        for i in range(7)
    ]
    ingest = client.post("/api/events/ingest", json={"events": events}, headers=headers)
    assert ingest.status_code == 200

    _wait_for(client, headers, "/api/events/", lambda j: len(j.get("items", [])) >= 1)
    test = client.post(f"/api/rules/{rule_id}/test", headers=headers, json={"minutes": 60})
    assert test.status_code == 200, test.text
    assert test.json()["evaluated"] >= 1
    assert test.json()["matched"] >= 1

    # Delete -> gone.
    delete = client.delete(f"/api/rules/{rule_id}", headers=headers)
    assert delete.status_code == 200
    assert client.get(f"/api/rules/{rule_id}", headers=headers).status_code in (404, 405)


def test_rule_test_records_audit(client):
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    rules = client.get("/api/rules/", headers=headers).json()["items"]
    rule_id = rules[0]["rule_id"]
    res = client.post(f"/api/rules/{rule_id}/test", headers=headers, json={"minutes": 30})
    assert res.status_code == 200
    audit = client.get("/api/system/audit", headers=headers).json()
    actions = {i.get("action") for i in audit["items"]}
    assert "rule.test" in actions
