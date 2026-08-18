# AI Sentinel

Real-time AI-powered cybersecurity detection, prevention, response & data protection platform.

AI Sentinel continuously monitors servers, applications, network traffic, authentication and file activity, and turns real telemetry into rule-based and ML-based detections, correlated incidents, alerts and controlled response actions — streamed live to an enterprise SOC dashboard over WebSocket.

**No fake security events.** Every event, alert, and incident is derived from real telemetry, logs, network events, or validated detection results. Demo/simulation mode is explicit and opt-in only.

---

## Stack

| Layer      | Technology |
|------------|------------|
| Backend    | FastAPI + Uvicorn (Python 3.13) |
| Frontend   | React 18 + Vite + Tailwind CSS |
| Database   | SQLite (WAL), retained across restarts |
| ML         | scikit-learn Isolation Forest (anomaly detection) |
| Streaming  | In-process async queue + authenticated WebSocket push |
| Auth       | PBKDF2-SHA256 password hashing, HMAC-signed tokens, RBAC |
| Deployment | Docker / Docker Compose |

---

## Repository layout

```
AI Sentinel/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI app, WS stream, static hosting
│   │   ├── core/              # config, security (auth/RBAC), deps
│   │   ├── pipeline/          # real-time event pipeline (workers, detections)
│   │   ├── engines/           # rule engine, sliding-window rules
│   │   ├── ml/                # Isolation Forest anomaly detector
│   │   ├── phishing/          # safe URL phishing analyzer
│   │   ├── telemetry/         # psutil-based system/network/process collectors
│   │   ├── services/          # WS manager, audit, threat-intel
│   │   ├── routes/            # REST API routers
│   │   └── db.py              # schema, storage, queries (parameterized)
│   └── tests/                 # pytest suite (57 tests: security hardening, realtime WS, rules, latency, API)
├── frontend/                  # React dashboard (Vite)
├── data/                      # SQLite database (created at runtime)
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

---

## Quick start (development)

### Prerequisites
- Python 3.11+
- Node.js 18+
- PowerShell (Windows) or bash

### 1) Backend

```powershell
cd backend
python -m venv ..\.venv            # or use venv/ if already present
..\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd ..
Copy-Item .env.example .env        # then edit .env with your secrets
cd backend
uvicorn app.main:app --reload --port 8000
```

On first start the backend creates the SQLite database and the initial `admin`
account. If `SENTINEL_ADMIN_PASSWORD` is not set, a random password is generated
and written to `backend/bootstrap_admin.txt` (rotate it after first login).

### 2) Frontend

```powershell
cd frontend
npm install
npm run dev
```

- Dashboard: http://localhost:5173
- API docs: http://localhost:8000/docs
- Health: http://localhost:8000/api/health

Vite proxies `/api` and `/ws` to the backend on port 8000, so no CORS work is
needed in development.

---

## Quick start (production, Docker)

```powershell
Copy-Item .env.example .env
# EDIT .env: SENTINEL_AUTH_SECRET must be a long random value, set
# SENTINEL_ADMIN_PASSWORD to a strong password of your choice.
docker compose up --build -d
```

The image builds the React dashboard and serves both the API and the UI from a
single container on port 8000: http://localhost:8000

Data is persisted in the `sentinel-data` Docker volume (survives container
restarts and rebuilds).

---

## Real-time event ingestion

Endpoints/agents push normalized events to:

```
POST /api/events/ingest        Authorization: Bearer <token or agent key>
```

```json
{
  "events": [
    {
      "ts": "2026-08-16T12:00:00Z",
      "event_type": "auth.failed_login",
      "source_ip": "203.0.113.50",
      "username": "bob",
      "details": {"reason": "invalid password"}
    }
  ]
}
```

Supported event types: `auth.login`, `auth.failed_login`, `auth.logout`,
`process.start`, `file.write`, `file.delete`, `file.rename`, `network.connection`,
`web.request`, `dns.query`, `user.account_change`, `service.stop`, plus telemetry
snapshots (`telemetry.system`, `telemetry.network`, ...). Detection rules live in
`backend/app/engines/rules.py` and are runtime-editable from the Rules page —
enable/disable, edit, create, delete, **test against stored history**, with
**immutable version history and rollback** (every change audited).

### Real-time latency SLA

Every event is stamped as it moves through the pipeline
(`processed_at` → `detected_at` → `alert_created_at` → `incident_created_at` →
`dashboard_delivered_at`). The pipeline tracks p50/p95/p99/max ingest→dashboard
latency per severity and reports SLA met % (targets:
`SENTINEL_LATENCY_TARGET_EVENT_MS`=2000, `SENTINEL_LATENCY_TARGET_CRITICAL_MS`=5000)
in `/api/system/metrics` and the System page.

### Endpoint agents

Agents authenticate with the shared `X-Agent-Key` header, report a heartbeat
(`POST /api/agents/heartbeat`), and are shown as HEALTHY / DEGRADED / OFFLINE on
the System page. The built-in psutil collector registers as `collector-<host>`.

### WebSocket live stream

```
GET /ws/events?token=<JWT>      (or Sec-WebSocket-Protocol: sentinel.<token>)
```

Messages: `hello`, `stats` (updated metrics), `event` (new normalized event),
`detection` (rule/ML detection), `alert` (new alert), `incident` (new/updated
incident). Each broadcast is stamped `sent_at` at send time. Bad tokens are
rejected with close code 4401.

---

## What gets detected

- **Brute force / credential attacks** — velocity of failed logins across a
  sliding window (accounts and source IP).
- **Web attacks** — SQL injection, XSS, command injection, path traversal
  (structural indicators, OWASP-aligned).
- **Ransomware-like behavior** — rapid bulk file writes/deletes/renames with
  high severity.
- **Data exfiltration** — unusual outbound transfer volumes per host.
- **Port scanning / recon** — connection fan-out across hosts and ports.
- **Anomalies** — Isolation Forest over telemetry and event features, with
  human-readable explanations grounded in the observed evidence.
- **Phishing** — safe static URL analysis (never follows links): look-alike
  domains, suspicious TLDs, IP-literal hosts, credential indicators, reputation
  (when threat-intel is configured). Verdict: SAFE / SUSPICIOUS / MALICIOUS.

Correlated attacks become incidents with a MITRE ATT&CK mapping, evidence
timeline, risk score, AI explanation and recommended response actions. See
`docs/detection_matrix.md` for the full matrix.

---

## Authentication & authorization

- Passwords hashed with PBKDF2-HMAC-SHA256 (210k iterations, unique salt).
- Tokens are HMAC-SHA256 signed, expiring claims (`SENTINEL_TOKEN_TTL`).
- Roles: `ADMIN`, `SOC_ANALYST`, `SECURITY_ENGINEER`, `VIEWER`.
- Every sensitive action (login, respond, alert updates, rule changes) is
  written to the audit log.

`admin`/`admin` does not exist and never will. The bootstrap password is random
or set via `SENTINEL_ADMIN_PASSWORD`.

---

## Response engine

Response actions (`ALERT_SOC`, `BLOCK_IP`, `ISOLATE_ENDPOINT`,
`PRESERVE_EVIDENCE`, `PROTECT_BACKUPS`, `QUARANTINE_FILE`, `REQUIRE_MFA`,
`REVOKE_SESSIONS`) are gated by policies. With
`SENTINEL_RESPONSE_DRY_RUN=true` (default) every action is **recorded but never
executed** — safe for evaluation. Set it to `false` only after real
integrations are configured.

---

## Testing

```powershell
cd backend
..\.venv\Scripts\python.exe -m pytest -q
```

57 tests cover password hashing, token signing, security hardening (prod config
guard, token revocation, RBAC, status validation, XFF/rate limiting, batch
limits), realtime WebSocket auth + live push, phishing→incident correlation,
rules CRUD/versioning/rollback/test, latency SLA + lifecycle timestamps, agent
heartbeats, detection rules, correlation/dedup, and the full API surface.
An optional live E2E smoke (`backend/scripts/e2e_smoke.py`, 27 checks) runs
against a running server. See `docs/testing.md`.

---

## Documentation

See `docs/` for: architecture diagram, API reference, WebSocket reference,
detection rules, ML architecture, attack detection matrix, incident-response
workflow, environment variables, security checklist, audit report, verification
report (A–F with honest blockers), and roadmap.

---

## Configuration

All settings are environment variables (see `.env.example` and
`docs/environment_variables.md`). Critical ones:

| Variable | Purpose |
|----------|---------|
| `SENTINEL_AUTH_SECRET` | HMAC secret for tokens — **must be set in production** |
| `SENTINEL_ADMIN_PASSWORD` | Bootstrap admin password |
| `SENTINEL_AGENT_KEY` | Key for endpoint agents pushing telemetry |
| `SENTINEL_DB_PATH` | SQLite path (default `data/sentinel.db`) |
| `SENTINEL_RETENTION_DAYS` | Event retention window (default 30) |
| `SENTINEL_RESPONSE_DRY_RUN` | Gate destructive response actions (default true) |
| `SENTINEL_ML_ENABLED` | Enable the Isolation Forest anomaly layer |
| `SENTINEL_DEMO_MODE` | Explicit, clearly-labelled simulation mode (default false) |
