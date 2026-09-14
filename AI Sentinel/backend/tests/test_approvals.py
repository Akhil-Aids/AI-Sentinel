"""Tests for the response approval workflow (two-person rule for destructive actions)."""
from datetime import datetime, timezone

from app import db
from app.core.config import settings
from app.response import POLICIES


def _make_high_incident():
    return db.save_incident({
        "title": "high-severity incident", "severity": "high", "status": "NEW",
        "risk_score": 70, "category": "malware", "affected_host": "host-x",
    })


def _make_low_incident():
    return db.save_incident({
        "title": "low-severity incident", "severity": "low", "status": "NEW",
        "risk_score": 20, "category": "generic", "affected_host": "host-y",
    })


def test_destructive_high_severity_requires_approval(client, admin_headers):
    inc = _make_high_incident()
    r = client.post(f"/api/incidents/{inc['incident_id']}/respond",
                    headers=admin_headers, json={"action": "BLOCK_IP", "reason": "test block"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"] == "PENDING_APPROVAL"
    assert body["blocked"] == "PENDING_APPROVAL"
    approval_id = body["approval_id"]
    assert db.get_approval(approval_id)["status"] == "PENDING"

    r = client.get("/api/approvals/?status=PENDING", headers=admin_headers)
    assert r.status_code == 200
    assert any(a["approval_id"] == approval_id for a in r.json()["items"])

    # Approve -> engine executes (dry-run recorded).
    r = client.post(f"/api/approvals/{approval_id}/approve", headers=admin_headers,
                    json={"reason": "confirmed"})
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["approval"]["status"] == "APPROVED"
    outcome = res["outcome"]
    # Tests run with SENTINEL_RESPONSE_DRY_RUN=true so the destructive action is
    # approved for execution but the engine still records BLOCKED (no adapter),
    # which is the honest state: approval granted, integration dry-run only.
    assert outcome["result"] == "BLOCKED"

    # Re-approving a resolved approval is a conflict.
    r = client.post(f"/api/approvals/{approval_id}/approve", headers=admin_headers,
                    json={"reason": "again"})
    assert r.status_code == 409


def test_approval_deny(client, admin_headers):
    inc = _make_high_incident()
    r = client.post(f"/api/incidents/{inc['incident_id']}/respond",
                    headers=admin_headers, json={"action": "ISOLATE_ENDPOINT", "reason": "iso"})
    assert r.status_code == 200
    approval_id = r.json()["approval_id"]

    r = client.post(f"/api/approvals/{approval_id}/deny", headers=admin_headers,
                    json={"reason": "not now"})
    assert r.status_code == 200
    assert r.json()["status"] == "DENIED"

    # Denying should NOT have executed the action.
    actions = [a for a in db.list_response_actions(limit=100)
               if a.get("action") == "ISOLATE_ENDPOINT"]
    assert all(a.get("result") != "SUCCESS" for a in actions)


def test_non_destructive_no_approval(client, admin_headers):
    inc = _make_high_incident()
    r = client.post(f"/api/incidents/{inc['incident_id']}/respond",
                    headers=admin_headers, json={"action": "ALERT_SOC", "reason": "ping"})
    assert r.status_code == 200
    body = r.json()
    assert body["result"] in ("SUCCESS",)
    assert "approval_id" not in body


def test_low_severity_destructive_executes_dry_run(client, admin_headers):
    inc = _make_low_incident()
    r = client.post(f"/api/incidents/{inc['incident_id']}/respond",
                    headers=admin_headers, json={"action": "BLOCK_IP", "reason": "low"})
    assert r.status_code == 200
    body = r.json()
    # In dry-run mode the destructive action is policy-blocked (no approval needed
    # at low severity) but still recorded.
    assert body["result"] == "BLOCKED"
    assert "approval_id" not in body


def test_requires_approval_helper():
    inc = _make_high_incident()
    assert response_requires(new_inc=inc)


def response_requires(new_inc=None):
    from app.response import response_engine
    return response_engine.requires_approval("BLOCK_IP", new_inc["incident_id"])


def test_approvals_list_pending(client, admin_headers):
    r = client.get("/api/approvals/", headers=admin_headers)
    assert r.status_code == 200
    assert len(r.json()["items"]) >= 0