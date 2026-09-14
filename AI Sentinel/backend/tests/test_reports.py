"""SOC reporting tests: daily / posture / incident report generation stored
with an audit trail, RBAC enforcement, and real (non-fabricated) content."""
from app import db


def _seed_activity(client):
    """Create a small real activity footprint for reports to summarize."""
    now_iso = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
    for i in range(3):
        db.save_event({"event_id": f"evt-rpt-{i}", "ts": now_iso,
                       "event_type": "auth.failed_login", "severity": "low",
                       "source_ip": "203.0.113.50", "host": "web-01"})
    db.save_alert({"alert_id": "alr-rpt-1", "title": "Brute force", "description": "d",
                   "severity": "high", "source": "brute_force_velocity"})
    db.save_incident({"incident_id": "inc-rpt-1", "title": "Campaign", "severity": "high",
                      "category": "credential-attack", "affected_host": "web-01"})


def test_daily_report_generated_and_stored(client, admin_headers):
    _seed_activity(client)
    res = client.post("/api/reports/daily", json={}, headers=admin_headers)
    assert res.status_code == 200, res.text
    report = res.json()
    assert report["report_type"] == "daily"
    content = report["content"]
    assert "alerts" in content and "incidents" in content and "events" in content
    # Never fabricated: events total must reflect seeds.
    assert content["events"]["total"] >= 3
    assert content["incidents"]["created"] >= 1
    assert report["period_start"] and report["period_end"]
    # Audit trail written.
    audit = client.get("/api/system/audit?limit=50&actor=admin", headers=admin_headers).json()["items"]
    assert any(a["action"] == "report.daily" for a in audit)


def test_posture_report_updates_score(client, admin_headers):
    res = client.post("/api/reports/posture", json={}, headers=admin_headers)
    assert res.status_code == 200, res.text
    content = res.json()["content"]
    assert content["security_score"]["score"] >= 0
    assert "hosts" in content and "recommendations" in content


def test_incident_report(client, admin_headers):
    inc = db.save_incident({"incident_id": "inc-rpt-detail", "title": "Phish",
                            "severity": "high", "affected_host": "web-01"})
    res = client.post(f"/api/reports/incident/{inc['incident_id']}", headers=admin_headers)
    assert res.status_code == 200, res.text
    content = res.json()["content"]
    assert content["incident"]["incident_id"] == inc["incident_id"]
    assert content["report_type"] == "incident"


def test_report_missing_incident_404(client, admin_headers):
    res = client.post("/api/reports/incident/nope-12345", headers=admin_headers)
    assert res.status_code == 404


def test_list_and_fetch_reports(client, admin_headers):
    res = client.get("/api/reports/", headers=admin_headers)
    assert res.status_code == 200
    items = res.json()["items"]
    assert any(r["report_type"] == "daily" for r in items)
    target = items[0]
    got = client.get(f"/api/reports/{target['report_id']}", headers=admin_headers)
    assert got.status_code == 200
    assert got.json()["report_id"] == target["report_id"]


def test_reports_invalid_type_rejected(client, admin_headers):
    res = client.get("/api/reports/?report_type=bogus", headers=admin_headers)
    assert res.status_code == 400


def test_reports_require_auth(client):
    assert client.get("/api/reports/").status_code == 401
    assert client.post("/api/reports/daily", json={}).status_code == 401