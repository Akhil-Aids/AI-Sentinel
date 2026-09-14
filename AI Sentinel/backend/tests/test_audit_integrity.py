"""Tamper-evident audit log hash chain (director requirement: integrity of the
audit trail must be verifiable)."""
import pytest

from app import db


@pytest.fixture(scope="module")
def client_audit(client):
    return client


def test_audit_records_have_chain_fields(admin_headers, client_audit):
    res = client_audit.get("/api/system/audit?limit=5", headers=admin_headers)
    assert res.status_code == 200, res.text
    items = res.json()["items"]
    assert items, "audit log should be non-empty"
    for item in items:
        assert item["prev_hash"] != "" or item["record_hash"] != ""
        assert isinstance(item["prev_hash"], str)
        assert isinstance(item["record_hash"], str)
        assert len(item["record_hash"]) == 64  # sha256 hex


def test_verify_endpoint_returns_ok(admin_headers, client_audit):
    res = client_audit.get("/api/system/audit/verify", headers=admin_headers)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["integrity"] == "OK"
    assert body["records"] >= 0
    assert body["tampered"] == []
    assert body["broken_links"] == []
    assert body["verified"] == body["records"]


def test_verify_requires_engineer(client, admin_headers):
    # Login as a viewer to confirm the privileged gate is real.
    import os
    from app.core.security import hash_password

    view_uname = f"viewer_aud_{os.getpid()}"
    db.create_user(view_uname, hash_password("some-viewer-pass-1"), "VIEWER")
    res = client.post("/api/auth/login", json={"username": view_uname, "password": "some-viewer-pass-1"})
    assert res.status_code == 200
    vtoken = res.json()["token"]
    vheaders = {"Authorization": f"Bearer {vtoken}"}
    res = client.get("/api/system/audit/verify", headers=vheaders)
    assert res.status_code == 403


def test_detect_tampered_record(client, admin_headers):
    before = db.verify_audit_chain()
    assert before["integrity"] == "OK"

    # Write an audit row directly, then mutate its detail behind the chain's back.
    db.log_audit(actor="integrity.probe", action="test.harness",
                 result="SUCCESS", detail={"step": 1})
    rows = db.list_audit(limit=3, actor="integrity.probe")
    assert rows, "probe row should exist"
    target = rows[0]["id"]

    conn = db.get_connection()
    conn.execute("UPDATE audit_logs SET detail = '{\"step\": 2}' WHERE id = ?", (target,))
    conn.commit()

    after = db.verify_audit_chain()
    assert after["integrity"] == "COMPROMISED"
    assert target in after["tampered"]

    # Repair the chain so later tests do not trip on damaged fixture state.
    db._rechain_audit()
    repaired = db.verify_audit_chain()
    assert repaired["integrity"] == "OK"


def test_chain_links_records_together(client_audit, admin_headers):
    """Record N+1 must reference record N's hash via prev_hash."""
    rows = db.list_audit(limit=4)
    # list_audit is ORDER BY ts DESC; flip to ascending id order.
    rows = sorted(rows, key=lambda r: r["id"])
    assert len(rows) >= 2
    for current, nxt in zip(rows, rows[1:]):
        assert nxt["prev_hash"] == current["record_hash"]


def test_backfill_legacy_rows(client_audit):
    """Rows written without hashes are chained at init_schema and then verify OK."""
    conn = db.get_connection()
    conn.execute(
        "INSERT INTO audit_logs(ts, actor, actor_role, action, target, result, ip, detail) "
        "VALUES('2099-01-01T00:00:00+00:00', 'legacy.backfill', '', 'insert.raw', '', 'SUCCESS', '', '{}')"
    )
    conn.commit()
    db._chain_audit()
    rows = db.list_audit(limit=5, actor="legacy.backfill")
    assert rows
    assert all(r["record_hash"] for r in rows)
    assert db.verify_audit_chain()["integrity"] == "OK"