"""Incident SLA engine: policy CRUD, time-based states, honesty rules."""
from datetime import datetime, timedelta, timezone

from app import db
from app.services import sla as sla_service


def _incident(incident_id, severity, created_at, status="NEW", resolved_at=None):
    return {
        "incident_id": incident_id, "severity": severity, "status": status,
        "created_at": created_at, "resolved_at": resolved_at,
    }


def test_default_policies_seeded(client, admin_headers):
    res = client.get("/api/sla/policies/", headers=admin_headers)
    assert res.status_code == 200, res.text
    items = res.json()["items"]
    assert len(items) >= 4
    by_sev = {p["severity"]: p for p in items}
    assert by_sev["critical"]["target_minutes"] == 30
    assert by_sev["high"]["target_minutes"] == 120


def test_policy_update_and_rbac(client, admin_headers):
    res = client.put("/api/sla/policies/critical", headers=admin_headers,
                     json={"target_minutes": 15, "enabled": True})
    assert res.status_code == 200, res.text
    assert res.json()["target_minutes"] == 15

    # non-admin rejected
    err = client.put("/api/sla/policies/critical", json={"target_minutes": 5, "enabled": True})
    assert err.status_code == 401

    bad = client.put("/api/sla/policies/bogus", headers=admin_headers,
                     json={"target_minutes": 5, "enabled": True})
    assert bad.status_code == 400

    db.upsert_sla_policy("critical", 30, True)  # restore


def test_sla_states_by_time():
    now = datetime.now(timezone.utc)
    # Critical resolved within 30 min -> MET
    met = _incident("inc-sla-met", "critical",
                    (now - timedelta(minutes=10)).isoformat(), status="RESOLVED",
                    resolved_at=(now - timedelta(minutes=5)).isoformat())
    assert sla_service.compute_sla(met)["state"] == "MET"

    # Resolved AFTER target -> BREACHED even though resolved
    breached = _incident("inc-sla-breached-resolved", "critical",
                         (now - timedelta(hours=3)).isoformat(), status="RESOLVED",
                         resolved_at=now.isoformat())
    assert sla_service.compute_sla(breached)["state"] == "BREACHED"

    # Still active but fresh -> WITHIN_SLA
    fresh = _incident("inc-sla-fresh", "high", (now - timedelta(minutes=5)).isoformat())
    state = sla_service.compute_sla(fresh)["state"]
    assert state in ("WITHIN_SLA", "APPROACHING")

    # Active past target -> BREACHED
    stale = _incident("inc-sla-stale", "critical", (now - timedelta(hours=2)).isoformat())
    assert sla_service.compute_sla(stale)["state"] == "BREACHED"

    # No policy for severity -> NO_TARGET (honest, never DEFAULT_SAFE)
    noctl = _incident("inc-sla-notarg", "bogus", now.isoformat())
    assert sla_service.compute_sla(noctl)["state"] == "NO_TARGET"


def test_sla_api_surface(client, admin_headers):
    # Save a breached incident directly.
    now = datetime.now(timezone.utc)
    db.save_incident(_incident("inc-sla-api", "critical",
                               (now - timedelta(hours=5)).isoformat()))
    items = client.get("/api/sla/incidents/?limit=50", headers=admin_headers).json()["items"]
    target = next((i for i in items if i["incident_id"] == "inc-sla-api"), None)
    assert target and target["sla"]["state"] == "BREACHED"
    detail = client.get("/api/sla/incidents/inc-sla-api", headers=admin_headers)
    assert detail.status_code == 200
    assert "state" in detail.json()


def test_incident_detail_includes_sla(client, admin_headers):
    now = datetime.now(timezone.utc)
    db.save_incident(_incident("inc-sla-detail", "high", (now - timedelta(minutes=2)).isoformat()))
    detail = client.get("/api/incidents/inc-sla-detail", headers=admin_headers).json()
    assert "sla" in detail
    assert "evidence_items" in detail
    assert "tasks" in detail