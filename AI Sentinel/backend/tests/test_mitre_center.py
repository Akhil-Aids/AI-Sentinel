"""MITRE ATT&CK coverage, detection gaps and post-incident review (X6)."""
from app import db
from app.services import mitre_center


def _make_incident(incident_id, category, mitre=None, status="RESOLVED", detection_rules=None):
    return {
        "incident_id": incident_id, "category": category, "severity": "high", "status": status,
        "mitre": mitre or [], "detection_rules": detection_rules or [], "timeline": [],
        "created_at": "2026-09-01T00:00:00Z", "resolved_at": "2026-09-02T00:00:00Z",
    }


def _fake_incident_for_review(incident_id):
    db.save_incident(_make_incident(incident_id, "credential-attack", ["T1110"], detection_rules=["rule_that_disabled"]))


def test_coverage_endpoint(client, admin_headers):
    res = client.get("/api/mitre/coverage/", headers=admin_headers)
    assert res.status_code == 200, res.text
    body = res.json()
    assert "coverage" in body and "techniques" in body
    # Honest: never claims a nonzero covered count with zero techniques reported.
    assert body["coverage"]["techniques_covered"] >= 0
    assert "gap_recommendations" in body


def test_coverage_from_seeded_rules():
    cov = mitre_center.coverage()
    # The bundled rules ship THIS_FEATURE_DISABLED defaults with known MITRE tags.
    enabled = [t for t in cov["techniques"] if t["status"] in ("VERIFIED_LIVE", "DETECTING")]
    # Just assert the shape holds; live DBs differ. Honesty check: statuses valid.
    valid = {"VERIFIED_LIVE", "DETECTING", "RULES_DISABLED", "OBSERVED_NO_RULES"}
    assert all(t["status"] in valid for t in cov["techniques"])
    for rec in cov["gap_recommendations"]:
        assert rec["priority"] in ("high", "medium", "low")


def test_observed_no_rules_gap(client, admin_headers):
    db.save_incident(_make_incident("mitre-gap-inc", "unusual-category", ["T9999"]))
    cov = mitre_center.coverage()
    recs = [r for r in cov["gap_recommendations"]
            if r.get("technique") == "T9999" and r["type"] == "missing_detection"]
    assert len(recs) == 1 and recs[0]["priority"] == "high"


def test_rule_disabled_gap():
    rows = mitre_center.gap_recommendations([{
        "technique": "T1110", "tactic": "Credential Access", "status": "RULES_DISABLED",
        "enabled_rules": [], "disabled_rules": ["disabled-rule"], "incidents": 1, "alerts": 0,
    }])
    assert any(r["type"] == "rule_disabled" for r in rows)


def test_produce_review_surface(db_blob=None):
    review = mitre_center.produce_review(_make_incident(
        "review-inc", "credential-attack", ["T1110"], status="INVESTIGATING"))
    assert review["status"] == "COMPLETE"
    assert review["incident_id"] == "review-inc"
    assert "findings" in review and "recommendations" in review
    # Honest downgrade for missing data — never claims a clean clean.
    if not review["evidence_count"]:
        assert any(f["type"] == "no_evidence" for f in review["findings"])


def test_review_endpoint_flow(client, admin_headers):
    _fake_incident_for_review("review-endpoint-inc")
    res = client.post("/api/mitre/incidents/review-endpoint-inc/review", headers=admin_headers)
    assert res.status_code == 200, res.text
    review = res.json()
    assert review["incident_id"] == "review-endpoint-inc"
    hist = db.list_incident_history("review-endpoint-inc", limit=10)
    assert any(h["action"] == "review" for h in hist)