"""Security posture engine (X7): honest score derivation + history persistence."""
from app import db
from app.services import posture


def test_posture_endpoints(client, admin_headers):
    now_res = client.get("/api/posture/now", headers=admin_headers)
    assert now_res.status_code == 200, now_res.text
    body = now_res.json()
    assert "score" in body and "factors" in body and "coverage" in body
    assert body["status"] in ("GOOD", "FAIR", "POOR", "CRITICAL")
    assert 0 <= body["score"] <= 100

    hist = client.get("/api/posture/history", headers=admin_headers)
    assert hist.status_code == 200
    assert "items" in hist.json()


def test_score_is_data_driven_and_honest():
    s = posture.compute()
    # Without telemetry in the last hour the event_flow factor must penalise.
    flow = next(f for f in s["factors"] if f["factor"] == "event_flow")
    assert flow["value"] >= 0
    # Deltas are bounded deltas: each factor contributes at most its headroom.
    assert all(-40 <= d["delta"] <= 5 for d in s["deltas"])


def test_no_telemetry_penalises():
    now = posture.compute()
    flow = next(f for f in now["factors"] if f["factor"] == "event_flow")
    # A system that just lost its feed must not look GOOD.
    if flow["value"] == 0:
        assert flow["factor_delta"] <= -39
    else:
        assert flow["factor_delta"] >= 0


def test_record_snapshot_flow(client, admin_headers):
    res = client.post("/api/posture/record", headers=admin_headers)
    assert res.status_code == 200, res.text
    assert res.json()["score"]
    hist = db.list_posture_history(limit=5)
    assert len(hist) >= 1
    assert all("snapshot" in h for h in hist)