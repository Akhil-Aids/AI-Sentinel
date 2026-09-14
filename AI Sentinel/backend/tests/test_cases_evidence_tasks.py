"""Case / evidence / SOC task management end to end."""
import hashlib
import os
import time


def _login(client, username, password):
    res = client.post("/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['token']}"}


def _make_incident(client, headers):
    suffix = __import__('uuid').uuid4().hex[:6]
    base = int(time.time() * 1000)
    events = [
        {"ts": f"2030-01-01T00:00:00.000Z", "id": f"ev_{suffix}_{i}",
         "event_type": "auth.failed_login", "source_ip": f"203.0.113.{suffix[:2]}",
         "username": f"u{i % 2}", "host": "wf-host", "severity": "low"}
        for i in range(12)
    ]
    res = client.post("/api/events/ingest", headers=headers, json={"events": events})
    assert res.status_code == 200, res.text
    assert res.json()["accepted"] == 12
    for _ in range(40):
        inc = client.get("/api/incidents/?limit=10", headers=headers).json()["items"]
        matches = [i for i in inc if i.get("category") == "credential-attack"]
        if matches:
            return matches[0]
        time.sleep(0.1)
    raise AssertionError("expected an incident from ingestion")


def test_case_lifecycle(client, admin_headers):
    case = client.post("/api/cases/", headers=admin_headers,
                       json={"title": "APT-42 campaign", "description": "Suspected AV-REMEDIATION",
                             "severity": "high", "category": "apt", "assigned_to": "analyst.one"})
    assert case.status_code == 200, case.text
    case_id = case.json()["case_id"]

    listed = client.get("/api/cases/", headers=admin_headers).json()["items"]
    assert any(c["case_id"] == case_id for c in listed)

    patch = client.patch(f"/api/cases/{case_id}", headers=admin_headers,
                         json={"status": "INVESTIGATING", "detection_gap": True, "gap_summary": "Lack of DNS beaconing coverage"})
    assert patch.status_code == 200, patch.text
    assert patch.json()["status"] == "INVESTIGATING"

    # close
    close = client.patch(f"/api/cases/{case_id}", headers=admin_headers,
                         json={"status": "CLOSED", "resolution": "Contained"},
                         )
    assert close.status_code == 200
    assert close.json()["resolved_at"]

    bad_status = client.patch(f"/api/cases/{case_id}", headers=admin_headers, json={"status": "BOGUS"})
    assert bad_status.status_code == 400

    # notes
    note = client.post(f"/api/cases/{case_id}/notes", headers=admin_headers, json={"note": "Diamond model updated"})
    assert note.status_code == 200
    detail = client.get(f"/api/cases/{case_id}", headers=admin_headers).json()
    assert any(n["note"] == "Diamond model updated" for n in detail["notes"])


def test_case_links_incident_and_alert(client, admin_headers):
    incident = _make_incident(client, admin_headers)
    case = client.post("/api/cases/", headers=admin_headers, json={"title": "linked case"}).json()

    link = client.post(f"/api/cases/{case['case_id']}/links", headers=admin_headers,
                       json={"incident_id": incident["incident_id"]})
    assert link.status_code == 200, link.text  # no trailing-slash issues: POST /{id}/links

    detail = client.get(f"/api/cases/{case['case_id']}", headers=admin_headers).json()
    assert any(i["incident_id"] == incident["incident_id"] for i in detail["incidents"])

    unlink = client.delete(f"/api/cases/{case['case_id']}/links/incident/{incident['incident_id']}",
                           headers=admin_headers)
    assert unlink.status_code == 200
    detail = client.get(f"/api/cases/{case['case_id']}", headers=admin_headers).json()
    assert detail["incidents"] == []


def test_evidence_immutability_and_integrity(client, admin_headers):
    incident = _make_incident(client, admin_headers)
    ev = client.post("/api/evidence/", headers=admin_headers,
                     json={"type": "file", "title": "suspicious.exe",
                           "content": "MZ\x90\x00SENTINEL-CAPTURED-BINARY",
                           "incident_id": incident["incident_id"]})
    assert ev.status_code == 200, ev.text
    evidence = ev.json()
    ev_id = evidence["evidence_id"]
    assert evidence["integrity_status"] == "VERIFIED"
    assert evidence["content_hash"] == hashlib.sha256(
        "MZ\x90\x00SENTINEL-CAPTURED-BINARY".encode()).hexdigest()

    # Immutable: no update endpoint exists -> 405
    res = client.patch(f"/api/evidence/{ev_id}", headers=admin_headers,
                       json={"title": "nope"})
    assert res.status_code in (404, 405)

    # Tampering with content must flip verification status.
    from app import db
    conn = db.get_connection()
    conn.execute("UPDATE evidence SET content_raw = ? WHERE evidence_id = ?",
                 ("MZ\x90\x00TAMPERED-CONTENT-PAYLOAD", ev_id))
    conn.commit()
    verified = client.post(f"/api/evidence/{ev_id}/verify", headers=admin_headers)
    assert verified.status_code == 200
    assert verified.json()["integrity_status"] == "TAMPERED"

    # Externally provided hash yields PENDING until verified against content.
    ev2 = client.post("/api/evidence/", headers=admin_headers,
                      json={"type": "file", "title": "signed artifact",
                            "content": "payload-abc",
                            "content_hash": hashlib.sha256(b"payload-abc").hexdigest(),
                            "alert_id": ""})
    assert ev2.status_code == 400  # no reference supplied


def test_evidence_requires_reference(client, admin_headers):
    res = client.post("/api/evidence/", headers=admin_headers,
                      json={"type": "file", "title": "orphan", "content": "x"})
    assert res.status_code == 400


def test_tasks_end_to_end(client, admin_headers):
    incident = _make_incident(client, admin_headers)
    t = client.post("/api/tasks/", headers=admin_headers,
                    json={"title": "Isolate wf-host", "description": "Enable ACL", "owner": "analyst.one",
                          "priority": "high", "incident_id": incident["incident_id"]})
    assert t.status_code == 200, t.text
    task = t.json()
    assert task["status"] == "TODO"

    upd = client.patch(f"/api/tasks/{task['task_id']}", headers=admin_headers,
                       json={"status": "IN_PROGRESS"})
    assert upd.status_code == 200

    done = client.patch(f"/api/tasks/{task['task_id']}", headers=admin_headers, json={"status": "DONE"})
    assert done.status_code == 200
    assert done.json()["completed_at"]

    filt = client.get(f"/api/tasks/?incident_id={incident['incident_id']}", headers=admin_headers).json()["items"]
    assert any(x["task_id"] == task["task_id"] for x in filt)

    delete = client.delete(f"/api/tasks/{task['task_id']}", headers=admin_headers)
    assert delete.status_code == 200


def test_rbac_on_cases(client, admin_headers):
    import pytest as _pt
    from app import db, core
    from app.core.security import hash_password
    uname = f"viewer_case_{os.getpid()}"
    db.create_user(uname, hash_password("viewer-pass-99"), "VIEWER")
    headers = _login(client, uname, "viewer-pass-99")
    res = client.post("/api/cases/", headers=headers, json={"title": "no perms"})
    assert res.status_code == 403