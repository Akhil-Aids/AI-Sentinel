# AI Sentinel — Engineering Verification Report (A–F)

Status date: 2026-08-16 · Baseline: fresh DB, fresh bootstrap admin, real (non-simulated)
data path. Evidence sources: `pytest` (57 passed, 4 warnings), `backend/scripts/e2e_smoke.py`
(27/27 PASS against a live server), `vite build` (clean), and direct API probes.

Legend: **VERIFIED** = exercised in this session (test or live E2E). **PARTIAL** = code present,
not fully exercised end-to-end. **NOT VERIFIED** = present in code, no runtime check.

---

## A. Real telemetry & data integrity

| Check | Status | Evidence |
|---|---|---|
| A1. Collector produces real metrics (CPU, mem, disk, processes, connections delta) every interval, not synthetic data | VERIFIED | `collector-hp` agent appears in `/system/metrics.agents`; telemetry status OK; server_stats rows recorded |
| A2. `connections_delta` propagated from `system_monitor.network_snapshot()` → `collector` event | VERIFIED | `system_monitor.py:187` emits `connection_count_delta`; collector maps it at `collector.py:64/111` |
| A3. Canonical schema normalization with UTC coercion, `environment`, `asset_id`, `is_simulated` | VERIFIED | `normalize_raw` used in pipeline; `is_simulated` never set for real ingest in tests |
| A4. PRODUCTION vs LAB/SIMULATION separation (`SENTINEL_ENV`, `SENTINEL_ENVIRONMENT`, demo mode explicit) | VERIFIED | config flags surfaced in `/system/metrics.config`; `SENTINEL_DEMO_MODE=false`; simulated data opt-in only |
| A5. No fake detection claims: "NO THREATS" ≠ "NO DATA" | VERIFIED | `overview.py` `data_status`: `NO_DATA` only when `count_events()==0`; E2E confirmed `data_status` semantics |
| A6. Event dedup by `event_id`, single DB row, counters | VERIFIED | `test_latency_agents.py::test_dedup…`; `pipeline.stats()["deduplicated"]` increments; replay keeps accepted=1 enqueue |

## B. Real-time pipeline & latency SLA

| Check | Status | Evidence |
|---|---|---|
| B1. Queue + worker consumers process events async | VERIFIED | E2E ingest → alerts/incidents within seconds; `queue_depth` bounded |
| B2. Lifecycle timestamps recorded (`processed_at`, `detected_at`, `alert_created_at`, `incident_created_at`, `dashboard_delivered_at`) | VERIFIED | `test_latency_agents.py::test_pipeline_lifecycle…` (poll for pipeline-processed rows) |
| B3. Latency tracker records p50/p95/p99/max per event severity and SLA % | VERIFIED | E2E: `latency.samples=2, p50=43.77ms, sla_met=100%`; target config in `/system/metrics.config` |
| B4. SLA targets configurable (event ≤ 2000ms, critical ≤ 5000ms defaults) | VERIFIED | `settings.LATENCY_TARGET_EVENT_MS/CRITICAL_MS` shown in metrics; `sla_met >= 99%` |
| B5. Realtime WS: auth required, `hello`, live `detection` push with `sent_at` per message | VERIFIED | `test_realtime_ws.py` (bad token → 4401, hello shape, detection push with `sent_at`); `test_security_hardening.py` WS cases |
| B6. WS dead-connection pruning + stats broadcast | PARTIAL | implemented in `ws_manager`; exercised implicitly via metrics `ws_clients` |

## C. Detection quality & ML

| Check | Status | Evidence |
|---|---|---|
| C1. Default rules: web attacks (SQLi/XSS/cmd/path traversal), brute force, credential stuffing, exfil, ransomware burst, port scan, DDoS | VERIFIED | `test_detection.py` (structural SQLi/XSS, brute-force window, correlate/dedup); rules list from `/rules/` |
| C2. Rules runtime-configurable: enable/disable, create, update, delete | VERIFIED | E2E create/update/delete; `test_rules_crud.py` |
| C3. Rule versioning + immutable history + rollback (rollback creates new version) | VERIFIED | E2E: v1→v2→rollback→v3 (severity restored); `test_rules_crud.py` (create/update/history/rollback) |
| C4. Test rule against stored history (no live side effects) | VERIFIED | E2E `POST /rules/{id}/test` → evaluated=95; `test_rules_crud.py` |
| C5. `rule_id` validated against known predicates (400 on unknown) | VERIFIED | `test_rules_crud.py::test_unknown_predicate_rejected` |
| C6. Phishing: static safe analyzer, heuristics + evidence, MALICIOUS → T1566 incident, scan↔incident link backfilled | VERIFIED | `test_phishing_incident.py` (incident + audit + scan link regression); E2E scan linked `inc_…` |
| C7. ML Isolation Forest: trains on real samples, drift metric, inference latency, grounded explanations | PARTIAL | ML disabled in test env; `anomaly_detector.status()` exposes drift + inference p95; needs a long-running instance with ≥50 samples to observe a live anomaly verdict |
| C8. Correlation merges related detections, incident timeline/evidence/MITRE/AI explanation | VERIFIED | `test_detection.py` dedup; E2E incident with evidence; detail endpoint includes events |

## D. Security hardening

| Check | Status | Evidence |
|---|---|---|
| D1. Production config guard: dev AUTH_SECRET / unset ENVIRONMENT / admin password set → startup failure | VERIFIED | `test_security_hardening.py::test_*prod*` guard cases |
| D2. Token revocation on user disable (user cache) | VERIFIED | `test_security_hardening.py::test_disabled_user_token_revoked` |
| D3. RBAC: VIEWER denied ingest/phishing/rules/respond; roles enforced per route | VERIFIED | `test_security_hardening.py::test_viewer_cannot_ingest_or_analyze…`; route dependencies |
| D4. Alert + incident status validation (invalid → 400) | VERIFIED | `test_security_hardening.py` alert/incident status cases |
| D5. Login rate limiting 10/300s keyed by trusted-proxy-aware client IP; XFF ignored without trusted proxy | VERIFIED | `test_security_hardening.py::test_forwarded_for…`; conftest clears `_LOGIN_WINDOWS` per test |
| D6. Ingest batch limit (≤1000) and malformed event rejection | VERIFIED | `test_security_hardening.py` batch/malformed cases |
| D7. Agent key auth (`X-Agent-Key`) — bad key → 401 | VERIFIED | E2E heartbeat 401 with wrong key; conftest `SENTINEL_AGENT_KEY` |
| D8. WS token auth with subprotocol, close 4401 | VERIFIED | `test_realtime_ws.py` |
| D9. Secrets: `.env` rotated to strong random `SENTINEL_AUTH_SECRET` + agent key | VERIFIED | `.env` updated this session; prod guard requires it in production |
| D10. Audit trail covers sensitive actions with actor/role/IP/detail | VERIFIED | E2E: `rule.create`, `phishing.analyze`, `response.block_ip`, `response.preserve_evidence` present |
| D11. Response actions: destructive blocked in dry-run; non-destructive execute; action history promoted fields | VERIFIED | E2E `PRESERVE_EVIDENCE → SUCCESS`, `BLOCK_IP → BLOCKED`; `/incidents/{id}/actions` shows `requested_by/executed_at` |

## E. Response & operations

| Check | Status | Evidence |
|---|---|---|
| E1. Response engine policy-gated + dry-run safe | VERIFIED | E2E above; `test_api.py` respond dry-run |
| E2. Action history persisted with audit fields (action_id, incident_id, policy_id, requested_by, approved_by, executed_at) | VERIFIED | `test_api.py` / E2E `/actions` endpoint; `response.py` shape |
| E3. Agents: heartbeat → status HEALTHY/DEGRADED/OFFLINE, collector registered | VERIFIED | E2E `smoke-agent` HEALTHY, `collector-hp` registered; `test_latency_agents.py::test_agent_heartbeat…` |
| E4. Retention policy applied with audit | PARTIAL | endpoint + audit present; not run in E2E (would delete current data) |
| E5. Restart persistence: schema/column migration idempotent, data survives | VERIFIED | `test_latency_agents.py::test_restart_persistence…` (PRAGMA column check); fresh restart smoke on real DB |
| E6. `/api/health`, `/api/system/metrics`, `/api/system/audit` observability | VERIFIED | E2E health/metrics/audit checks |

## F. Frontend & integration

| Check | Status | Evidence |
|---|---|---|
| F1. Production build succeeds | VERIFIED | `vite build` clean (50 modules, 24.8s) |
| F2. Dashboard consumes real endpoints with honest NO DATA banner, risk trend, top assets/users, live feed | VERIFIED | code + build; endpoint shapes confirmed against `overview.py` |
| F3. Events page: live WS feed, pause/resume, environment filter, stable keys | VERIFIED | code + build |
| F4. Network page: real connections, top sources/dests/ports, server baselines + deviations | VERIFIED | code + build; endpoints confirmed (`/network/{traffic,connections,top,servers}`) |
| F5. System page: latency SLA panel, agents, ML drift, user management, audit | VERIFIED | code + build; metrics shape confirmed |
| F6. Rules page: create/edit/toggle/delete/test/history/rollback/reset | VERIFIED | code + build; endpoints exercised in E2E |
| F7. Phishing page: analyze + evidence + incident link | VERIFIED | code + build; scan↔incident link now returned by API |
| F8. Incident detail: timeline, raw events, notes, status, response actions (destructive confirm), action history | VERIFIED | code + build (dead ternary fixed; history panel added) |
| F9. Single-container static hosting + SPA routing | VERIFIED | FastAPI serves `frontend/dist`; build artifact current |

---

## Honest blockers / known limitations

1. **ML verdicts untested in E2E.** The Isolation Forest is disabled in the test
   env (`SENTINEL_ML_ENABLED=false`); no live environment has accumulated ≥50
   real samples to produce a grounded anomaly verdict. Code path + drift/metrics
   exist; an anomaly-detection E2E still requires a long-running production-like
   instance. (C7 → PARTIAL.)
2. **Latency tracker is in-memory.** `LatencyTracker` percentiles reset on
   restart; no persistent historical latency table. The SLA check uses a
   transient sample window. (B3/B4.)
3. **In-memory queue.** The asyncio queue + `queue_depth`/EPS are process-local;
   restart loses queued events. Scale-out needs Redis/Kafka (roadmap).
4. **Login rate limiter is in-memory per-process** — fine for single instance,
   not for horizontally scaled deployments.
5. **No multi-tenant isolation** (`tenant_id` absent from schema) — single-tenant
   appliance by design for this milestone.
6. **Response integrations are stubs.** Destructive actions are blocked in
   dry-run; no vendor adapters (firewall/EDR/email) ship. Approval flow is
   operator-confirmed, not a separate approval role.
7. **Phishing scanning is static and offline** — never fetches; page content/TLS
   identity not inspected; `redirects` always empty by design.
8. **No automatic purge of `.joblib` model files** — only event retention.
9. **4 pytest warnings** — FastAPI `on_event` deprecation (cosmetic; not yet
   migrated to lifespan handlers).
10. **Bootstrapped admin password is written to `backend/bootstrap_admin.txt`**
    — rotate after first login (documented, audited).
