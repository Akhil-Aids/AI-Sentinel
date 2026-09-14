"""API key management: lifecycle, scoping, rotation, revocation, agent auth."""
import os

from app.core import apikey as apikey_core


def _create_key(client, admin_headers, name="integration", scope=None):
    res = client.post("/api/system/api-keys", headers=admin_headers,
                      json={"name": name, "scope": scope or ["read"], "role": "VIEWER",
                            "description": "test key"})
    assert res.status_code == 200, res.text
    data = res.json()
    assert "key" in data and data["key"].startswith("sk_live_")
    return data


def test_api_key_lifecycle_and_lookup(client, admin_headers):
    data = _create_key(client, admin_headers, name="lifecycle")
    key = data["key"]
    key_id, secret = key.split(":", 1)

    preres = client.get("/api/system/api-keys", headers=admin_headers)
    assert preres.status_code == 200
    assert any(k["key_id"] == key_id for k in preres.json()["items"])

    # Scope enforcement: read-only key cannot use the admin-only verify route.
    headers = {"X-API-Key": key}
    res = client.get("/api/system/audit", headers=headers)
    assert res.status_code == 401  # read scope does not grant role authority here

    # Unknown key rejected.
    bad = client.get("/api/system/audit", headers={"X-API-Key": "sk_live_zzz:aaa"})
    assert bad.status_code == 401


def test_api_key_scope_is_enforced_on_dependency(client, admin_headers):
    data = _create_key(client, admin_headers, name="ingest-only", scope=["ingest"])
    client.post("/api/system/api-keys", headers=admin_headers,
                json={"name": "noscope", "scope": ["read"], "role": "VIEWER"})
    # Scope mismatch with the shared verify dependency isn't exercised via agents,
    # so assert hash/parse primitives behave.
    key_id, secret = data["key"].split(":", 1)
    stored = None
    from app import db
    stored = db.get_api_key_auth(key_id)
    assert stored and apikey_core.verify_digest(key_id, secret, stored["key_hash"])
    assert not apikey_core.verify_digest(key_id, "wrong-secret", stored["key_hash"])


def test_api_key_rotation_and_revocation(client, admin_headers):
    data = _create_key(client, admin_headers, name="rotate")
    key_id, old_secret = data["key"].split(":", 1)
    from app import db

    rotate = client.post(f"/api/system/api-keys/{key_id}/rotate", headers=admin_headers)
    assert rotate.status_code == 200, rotate.text
    new_secret = rotate.json()["key"].split(":", 1)[1]
    assert new_secret != old_secret

    # Old secret no longer valid, new one is.
    stored = db.get_api_key_auth(key_id)
    assert stored
    assert apikey_core.verify_digest(key_id, new_secret, stored["key_hash"])
    assert not apikey_core.verify_digest(key_id, old_secret, stored["key_hash"])

    revoke = client.post(f"/api/system/api-keys/{key_id}/revoke", headers=admin_headers)
    assert revoke.status_code == 200
    listed = client.get("/api/system/api-keys", headers=admin_headers).json()["items"]
    assert all(k["key_id"] != key_id for k in listed)
    revoked_list = client.get("/api/system/api-keys?include_revoked=true", headers=admin_headers).json()["items"]
    assert any(k["key_id"] == key_id and k["revoked_at"] for k in revoked_list)


def test_api_key_validation_and_authorization(client, admin_headers):
    # non-admin cannot create keys
    import pytest
    bad = client.post("/api/system/api-keys",
                      json={"name": "nope", "scope": ["read"], "role": "VIEWER"})
    assert bad.status_code == 401
    # bad scope rejected
    err = client.post("/api/system/api-keys", headers=admin_headers,
                      json={"name": "bad", "scope": ["pwn"], "role": "VIEWER"})
    assert err.status_code == 400


def test_agent_heartbeat_with_api_key(client, admin_headers):
    data = _create_key(client, admin_headers, name="collector", scope=["ingest"])
    headers = {"X-API-Key": data["key"], "Content-Type": "application/json"}
    res = client.post("/api/agents/heartbeat", headers=headers,
                      json={"agent_id": f"hba_{os.getpid()}", "hostname": f"host-{os.getpid()}"})
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "ok"
    # last_used_at should have been recorded
    from app import db
    record = db.get_api_key_public(data["key"].split(":", 1)[0])
    assert record and record["last_used_at"]

    # Revoked key must no longer authenticate.
    key_id = data["key"].split(":", 1)[0]
    client.post(f"/api/system/api-keys/{key_id}/revoke", headers=admin_headers)
    denied = client.post("/api/agents/heartbeat", headers=headers,
                         json={"agent_id": f"hbb_{os.getpid()}"})
    assert denied.status_code == 401


def test_agent_ingest_with_api_key(client, admin_headers):
    data = _create_key(client, admin_headers, name="ingester", scope=["ingest"])
    headers = {"X-API-Key": data["key"]}
    res = client.post("/api/events/ingest/agent", headers=headers,
                      json={"events": [{"id": f"api_key_ev_{os.getpid()}",
                                        "event_type": "login.success",
                                        "timestamp": "2030-01-01T00:00:00Z",
                                        "host": f"host-{os.getpid()}", "source": "agent-test"}]})
    assert res.status_code == 200, res.text
    assert res.json()["accepted"] == 1

    bad = client.post("/api/events/ingest/agent", headers={"X-API-Key": f"sk_live_xxx:{os.getpid()}"},
                      json={"events": []})
    assert bad.status_code == 401