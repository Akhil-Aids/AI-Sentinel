# AI Sentinel — Testing Instructions

## Run the full suite

```powershell
cd backend
..\.venv\Scripts\python.exe -m pytest -q
```

Current suite: **57 tests passing** (security hardening, realtime WS, phishing →
incident, rules CRUD/versioning, latency & agents, detection, API).

Tests use an isolated temporary SQLite database (`%TEMP%/sentinel_test_…`),
with ML and threat-intel disabled and the response engine in dry-run. The
bootstrap admin password is fixed (`test-admin-pass-123`) for deterministic
login tests, and the agent key is `test-agent-key-123`.
**Tests never touch the production database or running server.**

## Live E2E smoke (against a real server)

```powershell
# fresh instance: start backend, then
..\.venv\Scripts\python.exe scripts\e2e_smoke.py
```

27 checks: login, health, overview/security-score shapes, agent heartbeat
(valid + bad key), real ingest, phishing MALICIOUS + scan→incident link, rules
create/update/test/history/rollback/delete, alerts/incidents, latency SLA,
agent visibility, response actions (dry-run semantics), audit trail, queue
bounds. Reads the bootstrap admin password automatically.

## Test files

### `tests/conftest.py`
- Sets environment variables **before** the app is imported (isolated DB,
  `SENTINEL_ADMIN_PASSWORD`, `SENTINEL_AGENT_KEY`, ML/TI off, dry-run on).
- Fixtures: `client` (FastAPI `TestClient`), `admin_token`, `admin_headers`,
  plus `TEST_PASSWORD` / `TEST_USERNAME`.
- Autouse `_clear_login_rate_limiter` clears `app.routes.auth._LOGIN_WINDOWS`
  per test (TestClient always presents one IP).

### `tests/test_security.py` — security unit tests
- Password hash roundtrip, wrong value, garbage hashes, unique salts.
- Token issue/decode, tampered token rejected (HTTPException), missing
  signature rejected, unknown role rejected.

### `tests/test_detection.py` — detection engine tests
- Sliding-window event counting and distinct-value queries.
- Brute-force predicate fires; structural SQLi/XSS detection.
- Correlator creates an incident and dedups the same campaign.
- Uses `_reset()` to clear events/incidents/alerts; some tests call the
  correlator directly, so their events lack pipeline timestamps — integration
  tests must poll for pipeline-processed rows instead of assuming timestamps.

### `tests/test_phishing.py` — phishing analyzer tests
- Safe URL → SAFE; obvious phish → MALICIOUS; IP-literal host → SUSPICIOUS;
  brand domain alone → not flagged; malformed input never crashes.

### `tests/test_api.py` — end-to-end API integration
- Public health, login, `/me`, token rejection, overview shape, ingest → list,
  rules list/reset, phishing analyze, grounded chatbot, full brute-force
  campaign → incident → respond (dry-run) → audit → system metrics.

### `tests/test_security_hardening.py`
- Production config guard (dev secret / unset environment / admin password).
- Token revocation after user disable; VIEWER RBAC (ingest/analyze blocked).
- Alert + incident status validation; XFF spoofing ignored without trusted
  proxy; login rate limit 429; ingest batch limit; malformed event rejection.

### `tests/test_realtime_ws.py`
- Bad WS token → close 4401 (`WebSocketDisconnect`); `hello` payload shape;
  live `detection` push carrying `sent_at` + `dashboard_delivered_at`.

### `tests/test_phishing_incident.py`
- MALICIOUS verdict → correlated incident (T1566) + `phishing.analyze` audit;
  originating scan row backfilled with its `incident_id`.

### `tests/test_rules_crud.py`
- Create/update with versioning, immutable history, rollback (new version),
  test-against-history, delete; unknown predicate → 400; `rule.test` audited.

### `tests/test_latency_agents.py`
- Latency p50/p95/p99/max/SLA; pipeline lifecycle timestamps via polling;
  dedup counter + single row; restart persistence (`init_schema` idempotent +
  PRAGMA column check); agent heartbeat → HEALTHY; agent-key ingest.

## Manual smoke checks

1. Start backend (see `docs/deployment.md`).
2. `GET /api/health` → `{"status":"ok", ...}`.
3. Login → token.
4. `POST /api/events/ingest` with 12 `auth.failed_login` events from one IP
   across 2 accounts → within seconds: 1 alert + 1 incident, WS `detection`
   push.
5. `POST /api/phishing/analyze` with `http://paypa1-login.com@<ip>/verify?token=…&password=…`
   → MALICIOUS, then a phishing incident + scan link.
6. `POST /api/rules/` (valid predicate `rule_id`) → version 1; PUT → v2;
   GET history; POST rollback → v3; POST test.
7. `POST /api/incidents/{id}/respond` with `BLOCK_IP` → `BLOCKED` (dry-run);
   `PRESERVE_EVIDENCE` → `SUCCESS`.
8. `POST /api/chatbot/` with "what is the risk level?" → grounded answer.
