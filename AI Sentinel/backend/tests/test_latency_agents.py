"""Latency instrumentation, event lifecycle columns, dedup, agent heartbeat
status, and restart persistence (idempotent schema re-init)."""
import time

from conftest import TEST_PASSWORD, TEST_USERNAME

AGENT_KEY = "test-agent-key-123"


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


def test_latency_metrics_reported(client):
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    res = client.get("/api/system/metrics", headers=headers)
    assert res.status_code == 200
    body = res.json()
    assert "latency" in body["pipeline"]
    latency = body["pipeline"]["latency"]
    for key in ("p50_ms", "p95_ms", "p99_ms", "sla_met_pct", "target_event_ms"):
        assert key in latency, key


def test_event_lifecycle_columns_populated(client):
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    events = [
        {"ts": f"2026-08-16T16:0{i}:00+00:00", "event_type": "auth.failed_login",
         "source_ip": "203.0.113.90", "username": f"u{i % 2}"}
        for i in range(12)
    ]
    client.post("/api/events/ingest", json={"events": events}, headers=headers)

    # Every processed event must carry the pipeline lifecycle timestamps. Poll
    # until a processed event is visible (the row appears before the update).
    processed = _wait_for(
        client, headers, "/api/events/",
        lambda j: any(e.get("processed_at") for e in j.get("items", [])), timeout=20.0)
    assert processed, "no processed event observed"
    ev = next(e for e in processed["items"] if e.get("processed_at"))
    for key in ("normalized_at", "processed_at", "source_type", "environment", "is_simulated", "ts"):
        assert ev.get(key) is not None, f"missing lifecycle column {key}"

    # The brute-force campaign above must create an incident via the pipeline;
    # the correlated event must carry the full detection timeline. (Some other
    # unit tests create incidents by calling the correlator directly, so poll
    # for an event that actually went through the pipeline.)
    def _timelined_event():
        res = client.get("/api/incidents/", headers=headers)
        if res.status_code != 200:
            return None
        for i in res.json().get("items", []):
            if i["category"] != "credential-attack":
                continue
            detail = client.get(f"/api/incidents/{i['incident_id']}", headers=headers).json()
            for eid in detail.get("event_ids", [])[:5]:
                ev = client.get(f"/api/events/{eid}", headers=headers).json()
                if ev.get("detected_at"):
                    return ev
        return None

    ev2 = None
    deadline = time.time() + 20
    while time.time() < deadline and ev2 is None:
        ev2 = _timelined_event()
        if ev2 is None:
            time.sleep(0.5)
    assert ev2, "no pipeline-correlated detection event observed"
    for key in ("detected_at", "correlated_at", "alert_created_at", "incident_created_at",
                "dashboard_delivered_at"):
        assert ev2.get(key) is not None, f"missing detection-timeline column {key}"


def test_duplicate_event_id_deduplicated(client):
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"events": [{"event_id": "dedup-abc-123", "event_type": "info.unique", "host": "h1"}]}
    first = client.post("/api/events/ingest", json=payload, headers=headers)
    assert first.json()["accepted"] == 1
    time.sleep(0.5)  # let the first event finish processing before the replay
    before = client.get("/api/system/metrics", headers=headers).json()["pipeline"]["deduplicated"]
    second = client.post("/api/events/ingest", json=payload, headers=headers)
    assert second.json()["accepted"] == 1  # accepted = enqueued (not yet deduped)
    deadline = time.time() + 10
    while time.time() < deadline:
        after = client.get("/api/system/metrics", headers=headers).json()["pipeline"]["deduplicated"]
        if after > before:
            break
        time.sleep(0.4)
    assert after > before, "replayed event_id was not counted as a duplicate"

    # And only one row exists for that event_id.
    from app import db
    rows = db._fetch_all("SELECT event_id FROM events WHERE event_id = ?", ("dedup-abc-123",))
    assert len(rows) == 1


def test_restart_persistence(client):
    """Re-running schema init (as on process restart) is idempotent and data survives."""
    from app import db
    before = db.count_events()
    db.init_schema()
    after = db.count_events()
    assert after == before
    assert before >= 1
    # New columns exist on a live table.
    cols = [r[1] for r in db._conn.execute("PRAGMA table_info(events)").fetchall()]
    for col in ("source_type", "environment", "asset_id", "is_simulated",
                "normalized_at", "processed_at", "detected_at", "correlated_at",
                "alert_created_at", "incident_created_at", "dashboard_delivered_at"):
        assert col in cols, col


def test_agent_heartbeat_and_status(client):
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    bad = client.post("/api/agents/heartbeat", headers={"X-Agent-Key": "wrong"},
                      json={"agent_id": "win-box-01", "hostname": "win-box-01"})
    assert bad.status_code == 401

    ok = client.post("/api/agents/heartbeat", headers={"X-Agent-Key": AGENT_KEY},
                     json={"agent_id": "win-box-01", "hostname": "win-box-01",
                           "os": "windows", "environment": "production",
                           "cpu": 12.0, "memory": 40.0, "processes": 320})
    assert ok.status_code == 200
    assert ok.json()["status"] == "ok"

    status = client.get("/api/agents/", headers=headers).json()
    agents = {a["agent_id"]: a for a in status["items"]}
    assert "win-box-01" in agents
    assert agents["win-box-01"]["status"] == "HEALTHY"

    collector = client.get("/api/agents/collector", headers=headers).json()
    assert collector["agent_id"].startswith("collector-")

    # Agent keyed ingestion works, user gating untouched.
    ingest = client.post("/api/events/ingest/agent", headers={"X-Agent-Key": AGENT_KEY},
                         json={"events": [{"event_type": "process.exec", "host": "win-box-01"}]})
    assert ingest.status_code == 200
    assert ingest.json()["accepted"] == 1


def test_agent_status_age_detection():
    from app.routes.agents import agent_status
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    assert agent_status((now - timedelta(seconds=5)).isoformat()) == "HEALTHY"
    assert agent_status((now - timedelta(seconds=60)).isoformat()) == "DEGRADED"
    assert agent_status((now - timedelta(seconds=600)).isoformat()) == "OFFLINE"
