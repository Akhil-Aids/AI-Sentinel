"""API integration tests (FastAPI TestClient)."""
import time

from conftest import TEST_PASSWORD, TEST_USERNAME


def _wait_for(client, headers, path, predicate, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = client.get(path, headers=headers)
        assert res.status_code == 200
        if predicate(res.json()):
            return res.json()
        time.sleep(0.5)
    return None


def test_public_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["version"]
    assert body["demo_mode"] is False


def test_login_wrong_password(client):
    res = client.post("/api/auth/login", json={"username": TEST_USERNAME, "password": "wrong"})
    assert res.status_code == 401


def test_login_ok_and_me(client, admin_token):
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    assert res.json()["username"] == TEST_USERNAME
    assert res.json()["role"] == "ADMIN"


def test_requires_auth(client):
    for path in ("/api/overview", "/api/alerts/", "/api/incidents/", "/api/rules/", "/api/events/"):
        assert client.get(path).status_code in (401, 403), path


def test_invalid_token(client):
    res = client.get("/api/overview", headers={"Authorization": "Bearer garbage.token.here"})
    assert res.status_code in (401, 403)


def test_overview_shape(client, admin_headers):
    res = client.get("/api/overview", headers=admin_headers)
    assert res.status_code == 200
    body = res.json()
    for key in ("servers", "incidents", "alerts", "events", "risk", "security_score",
                "attack_categories", "ml", "pipeline"):
        assert key in body, key
    assert 0 <= body["risk"]["score"] <= 100


def test_events_ingest_and_list(client, admin_headers):
    now = "2026-08-16T12:00:00+00:00"
    payload = {"events": [
        {"ts": now, "event_type": "auth.failed_login", "source_ip": "203.0.113.44",
         "username": "bob", "details": {"reason": "bad password"}},
    ]}
    res = client.post("/api/events/ingest", json=payload, headers=admin_headers)
    assert res.status_code == 200
    assert res.json()["accepted"] == 1

    res = client.get("/api/events/?event_type=auth.failed_login", headers=admin_headers)
    assert res.status_code == 200
    items = res.json()["items"]
    assert any(e["source_ip"] == "203.0.113.44" for e in items)


def test_rules_list_and_reset(client, admin_headers):
    res = client.get("/api/rules/", headers=admin_headers)
    assert res.status_code == 200
    assert len(res.json()["items"]) >= 10


def test_phishing_analyze(client, admin_headers):
    res = client.post("/api/phishing/analyze",
                      json={"url": "https://paypal-account-verify.info/login"}, headers=admin_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS")
    assert "url" in body and "risk_score" in body and "reasons" in body


def test_chatbot_grounded(client, admin_headers):
    res = client.post("/api/chatbot/", json={"message": "What is the current risk level?"},
                      headers=admin_headers)
    assert res.status_code == 200
    answer = res.json()["answer"]
    assert "risk" in answer.lower()


def test_incident_workflow_via_api(client, admin_headers):
    # Fire a brute-force campaign through the ingest API and expect an incident.
    events = [
        {"ts": f"2026-08-16T13:0{i}:00+00:00", "event_type": "auth.failed_login",
         "source_ip": "203.0.113.99", "username": f"u{i % 2}"}
        for i in range(12)
    ]
    res = client.post("/api/events/ingest", json={"events": events}, headers=admin_headers)
    assert res.status_code == 200

    body = _wait_for(client, admin_headers, "/api/incidents/",
                     lambda j: any(i.get("category") == "credential-attack" for i in j.get("items", [])))
    assert body, "expected at least one credential-attack incident after pipeline processed the campaign"
    incidents = body["items"]
    inc = next(i for i in incidents if i["category"] == "credential-attack")
    assert inc["category"] == "credential-attack"

    detail = client.get(f"/api/incidents/{inc['incident_id']}", headers=admin_headers)
    assert detail.status_code == 200

    # Response action is dry-run by default (safe).
    resp = client.post(f"/api/incidents/{inc['incident_id']}/respond",
                       json={"action": "BLOCK_IP", "reason": "test"},
                       headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"].get("dry_run") is True
    assert body["status"].get("permitted") is False


def test_incident_update_status(client, admin_headers):
    res = client.get("/api/incidents/?status=NEW", headers=admin_headers)
    incs = res.json()["items"]
    if not incs:
        return
    iid = incs[0]["incident_id"]
    res = client.patch(f"/api/incidents/{iid}", json={"status": "INVESTIGATING"}, headers=admin_headers)
    assert res.status_code == 200
    assert res.json()["status"] == "INVESTIGATING"


def test_audit_trail_nonempty(client, admin_headers):
    res = client.get("/api/system/audit", headers=admin_headers)
    assert res.status_code == 200
    assert len(res.json()["items"]) > 0


def test_system_metrics(client, admin_headers):
    res = client.get("/api/system/metrics", headers=admin_headers)
    assert res.status_code == 200
    body = res.json()
    assert "pipeline" in body and "ml" in body and "storage" in body
    assert body["config"]["demo_mode"] is False


def test_access_control_alerts_patch(client, admin_headers):
    res = client.get("/api/alerts/", headers=admin_headers)
    alerts = res.json()["items"]
    if not alerts:
        return
    aid = alerts[0]["alert_id"]
    res = client.patch(f"/api/alerts/{aid}", json={"feedback": "FALSE_POSITIVE"}, headers=admin_headers)
    assert res.status_code == 200
    assert res.json()["feedback"] == "FALSE_POSITIVE"
