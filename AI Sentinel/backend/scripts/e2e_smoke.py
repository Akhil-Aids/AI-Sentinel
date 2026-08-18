"""E2E smoke: fresh instance, real (non-simulated) data path."""
import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000/api"
PASS = []
FAIL = []


def _load_env_key():
    import os
    if os.environ.get("SENTINEL_AGENT_KEY"):
        return os.environ["SENTINEL_AGENT_KEY"]
    from pathlib import Path
    env_file = Path(__file__).resolve().parent.parent.parent / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("SENTINEL_AGENT_KEY="):
                return line.partition("=")[2].strip()
    return ""


AGENT_KEY = _load_env_key()


def load_admin():
    from pathlib import Path
    lines = Path(__file__).resolve().parent.parent.joinpath("app/bootstrap_admin.txt").read_text().splitlines()
    creds = {}
    for ln in lines:
        if "=" in ln and not ln.startswith("Rotate"):
            k, _, v = ln.partition("=")
            creds[k.strip()] = v.strip()
    return creds.get("username", "admin"), creds.get("password", "")


ADMIN = load_admin()


def req(method, path, body=None, token=None, headers=None, raw=False):
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if headers:
        h.update(headers)
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            text = resp.read().decode()
            return resp.status, (text if raw else json.loads(text))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'}: {name}" + (f"  [{extra}]" if extra else ""))


# 1. login
st, body = req("POST", "/auth/login", {"username": ADMIN[0], "password": ADMIN[1]})
check("login", st == 200 and "token" in body, body.get("detail", ""))
if st != 200:
    print("Cannot continue without login."); sys.exit(1)
tok = body["token"]

# 2. health
st, body = req("GET", "/health", token=tok)
check("health ok", st == 200 and body.get("status") == "ok")

# 3. overview shape (built-in collector may already be flowing)
st, body = req("GET", "/overview", token=tok)
check("overview ok", st == 200 and body.get("data_status") in ("OK", "NO_EVENTS_TODAY", "NO_DATA"), str(body.get("data_status")))
check("security_score dict", isinstance(body.get("security_score"), dict) and "score" in body.get("security_score", {}), str(body.get("security_score")))

# 4. agent heartbeat via shared key (POST /agents/heartbeat)
st, body = req("POST", "/agents/heartbeat", {"agent_id": "smoke-agent", "hostname": "smoke-host", "os": "win", "cpu": 2.1, "memory": 34.0, "disk": 55.0, "processes": 120, "environment": "production"}, headers={"X-Agent-Key": AGENT_KEY})
check("agent heartbeat via key", st == 200 and body.get("status") == "ok" and body.get("agent_id") == "smoke-agent", str(body))

# 5. bad agent key rejected
st, body = req("POST", "/agents/heartbeat", {"agent_id": "smoke-agent"}, headers={"X-Agent-Key": "wrong"})
check("bad agent key 401", st == 401, str(st))

# 6. ingest REAL events
events = [
    {"event_type": "process.exec", "ts": "2026-08-16T10:00:00.000Z", "host": "smoke-host",
     "source_ip": "10.0.0.9", "username": "alice", "risk_score": 88, "severity": "high",
     "process_name": "powershell.exe", "command": "Invoke-Mimikatz", "details": {"pid": 4242}},
    {"event_type": "network.connection", "ts": "2026-08-16T10:00:01.000Z", "host": "smoke-host",
     "source_ip": "10.0.0.9", "dest_ip": "45.155.205.233", "dest_port": 4444, "risk_score": 90,
     "severity": "critical", "details": {"proto": "tcp"}},
]
st, body = req("POST", "/events/ingest", {"events": events}, token=tok)
check("ingest accepted", st == 200 and body.get("accepted") == 2, str(body))

# 7. phishing analyze (multiple strong signals) -> MALICIOUS + incident
phish_url = "http://paypa1-login.com@45.155.205.233/account/verify?token=abc&password=x"
st, body = req("POST", "/phishing/analyze", {"url": phish_url}, token=tok)
check("phishing malicious", st == 200 and body.get("verdict") == "MALICIOUS", body.get("verdict"))

# wait for pipeline to correlate the MALICIOUS scan into an incident
phish_inc = None
for _ in range(10):
    st, body = req("GET", "/phishing/scans", token=tok)
    scans = body.get("items") or []
    scan = next((s for s in scans if s.get("url") == phish_url), None)
    if scan and scan.get("incident_id"):
        phish_inc = scan["incident_id"]
        break
    time.sleep(1)
check("phishing scan linked to incident", bool(phish_inc), str(scan.get("incident_id") if scan else None))

# 8. rules CRUD + versioning
st, body = req("POST", "/rules/", {"rule_id": "count_events_gt", "name": "E2E burst", "description": "smoke", "category": "generic", "enabled": False, "severity": "medium", "mitre": [], "config": {"threshold": 5}}, token=tok)
check("create rule", st == 200 and body.get("version") == 1, str(st))
st, body = req("PUT", "/rules/count_events_gt", {"rule_id": "count_events_gt", "name": "E2E burst v2", "description": "smoke2", "category": "generic", "enabled": True, "severity": "high", "mitre": [], "config": {"threshold": 3}}, token=tok)
check("update rule v2", st == 200 and body.get("version") == 2, str(body.get("version")))
st, body = req("POST", "/rules/count_events_gt/test", {"minutes": 60, "limit": 500}, token=tok)
check("test rule against history", st == 200 and "evaluated" in body, str(body.get("evaluated")))
st, body = req("GET", "/rules/count_events_gt/history", token=tok)
check("rule history", st == 200 and body.get("current_version") == 2 and len(body.get("items", [])) >= 2, str(body.get("current_version")))
st, body = req("POST", "/rules/count_events_gt/rollback", {"version": 1}, token=tok)
check("rollback creates new version", st == 200 and body.get("version") == 3 and body.get("severity") == "medium", f"v{body.get('version')} sev={body.get('severity')}")
st, body = req("DELETE", "/rules/count_events_gt", token=tok)
check("delete rule", st == 200, str(st))

# 9. wait for pipeline to process real events -> alerts/incidents
time.sleep(4)
st, body = req("GET", "/alerts/?limit=20", token=tok)
alerts = body.get("items", [])
check("real alerts generated", len(alerts) >= 1, f"{len(alerts)} alerts")
st, body = req("GET", "/incidents/?limit=20", token=tok)
incidents = body.get("items", [])
check("incidents created", len(incidents) >= 1, f"{len(incidents)} incidents")

# 10. latency + metrics after processing
st, body = req("GET", "/system/metrics", token=tok)
lat = (body.get("pipeline") or {}).get("latency") or {}
check("latency samples recorded", lat.get("samples", 0) >= 1, f"{lat.get('samples')} samples p50={lat.get('p50_ms')}ms")
check("sla_met >= 99%", (lat.get("sla_met_pct") or 100) >= 99, str(lat.get("sla_met_pct")))
agents = body.get("agents") or []
check("smoke agent visible", any(a.get("agent_id") == "smoke-agent" for a in agents), str([a.get("agent_id") for a in agents]))
check("telemetry OK", (body.get("telemetry") or {}).get("status") == "OK", str((body.get("telemetry") or {}).get("status")))
check("collector agent registered", any(str(a.get("agent_id")).startswith("collector-") for a in agents), str([a.get("agent_id") for a in agents]))

# 11. response actions: permitted non-destructive executes; destructive blocked in dry-run
target = incidents[0]["incident_id"]
st, body = req("POST", f"/incidents/{target}/respond", {"action": "PRESERVE_EVIDENCE", "reason": "e2e smoke"}, token=tok)
check("preserve_evidence executes", st == 200 and body.get("result") == "SUCCESS", str(body.get("result")))
st, body = req("POST", f"/incidents/{target}/respond", {"action": "BLOCK_IP", "reason": "e2e smoke"}, token=tok)
check("destructive blocked in dry-run", st == 200 and body.get("result") == "BLOCKED", str(body.get("result")))
st, body = req("GET", f"/incidents/{target}/actions", token=tok)
acts = body.get("items") or []
check("action history promoted fields", len(acts) >= 1 and acts[0].get("requested_by", "").startswith("admin") and acts[0].get("created_at"), str([a.get("action") for a in acts][:4]))

# 12. audit trail has entries
st, body = req("GET", "/system/audit?limit=50", token=tok)
audit = body.get("items") or []
actions = {a.get("action") for a in audit}
check("audit actions present", {"rule.create", "phishing.analyze", "response.preserve_evidence", "response.block_ip"}.issubset(actions), str(sorted(actions)[:10]))

# 13. WS broadcast available (server metric) + queue healthy
check("queue_depth bounded", (body.get("pipeline") or {}).get("queue_depth", 0) < 20000, str((body.get("pipeline") or {}).get("queue_depth")))

print(f"\n{'='*50}\nPASS {len(PASS)} / FAIL {len(FAIL)}")
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
