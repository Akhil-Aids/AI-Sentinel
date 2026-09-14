# AI Sentinel

Real-time AI-powered cybersecurity SOC platform for detection, response, reporting, and live operational monitoring.

AI Sentinel continuously monitors servers, applications, network traffic, authentication, and file activity. Real telemetry flows through a production event pipeline where rule-based and ML-based detectors identify threats, correlate attacks into incidents with MITRE ATT&CK mappings, and stream everything live to an enterprise SOC dashboard over authenticated WebSocket — with full audit trail, SOC response metrics, reporting, and notification support.

**No fake security events.** Every event, alert, and incident is derived from real telemetry, logs, network events, or validated detection results. Simulation mode is strictly opt-in, off by default, and every generated artifact is permanently marked `is_simulated=1` with a visible DEMO banner in the UI.

---

## Key Features

- **Real-time telemetry**: psutil-based host/network/process collector; events ingested and pushed to dashboards in <2 seconds.
- **Rule engine + ML**: sliding-window rules (brute force, ransomware, exfil, port scan, web attacks) plus Isolation Forest anomaly detector.
- **Incident correlation**: multi-alert correlation, MITRE ATT&CK mapping, risk scoring, evidence timeline, recommended response actions.
- **Host investigation view**: per-host risk score, alert/incident linkage, CPU/memory history, network activity, recent events.
- **SOC response metrics**: MTTD, MTTA, MTTR computed from real acknowledged/resolved alert timestamps.
- **Reporting**: on-demand daily, security posture, and incident reports with full audit trail; stored in DB with RFC-2822 timestamps.
- **Notifications**: in-app notifications (unread badge, mark read / mark all) + optional webhook channel (Slack, Teams, PagerDuty). Webhook reports `NOT_CONFIGURED` honestly when no URL is set.
- **Enterprise auth**: PBKDF2-SHA256 password hashing, HMAC-signed JWTs, four-tier RBAC (ADMIN, SOC_ANALYST, SECURITY_ENGINEER, VIEWER), every sensitive action audit-logged.
- **Response engine**: policy-gated actions (BLOCK_IP, ISOLATE_ENDPOINT, QUARANTINE_FILE, etc.) in safe dry-run mode by default.
- **Threat intelligence**: optional VirusTotal and AbuseIPDB integration (API keys required; status shown honestly as `NOT_CONFIGURED` when absent).
- **Live UI**: dark-mode React dashboard, WebSocket live feed, connection status indicator, notification bell, demo mode banner when active.
- **Docker-ready**: single container build (backend + static frontend); SQLite WAL persistence in a named volume.

---

## Stack

| Layer | Technology |
|-------|------------|
| Backend | FastAPI + Uvicorn (Python 3.13) |
| Frontend | React 18 + Vite + Tailwind CSS |
| Database | SQLite (WAL), retained across restarts |
| ML | scikit-learn Isolation Forest |
| Streaming | In-process async queue + authenticated WebSocket push |
| Auth | PBKDF2-SHA256, HMAC-signed tokens, RBAC |
| Deployment | Docker / Docker Compose |

---

## Repository Layout

```
AI Sentinel/
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI app, lifespan, WS stream, readiness probe
│   │   ├── core/                 # config.py (env vars), security.py (auth/RBAC), deps.py
│   │   ├── pipeline/             # real-time event pipeline (workers, detections)
│   │   ├── engines/              # rule engine, sliding-window rules
│   │   ├── ml/                   # Isolation Forest anomaly detector
│   │   ├── phishing/             # safe URL phishing analyzer
│   │   ├── telemetry/            # psutil collectors, demo mode generator
│   │   ├── services/             # metrics (MTTD/MTTA/MTTR), notify, WS manager, audit
│   │   ├── reports.py            # report builders (daily, posture, incident)
│   │   ├── routes/               # REST API routers (70 routes)
│   │   │   ├── health.py         # /api/system/health, /metrics, /audit
│   │   │   ├── reports.py        # /api/reports (daily, posture, incident)
│   │   │   ├── notifications.py  # /api/notifications
│   │   │   ├── hosts.py          # /api/hosts (list + investigation view)
│   │   │   └── ...
│   │   └── db.py                 # schema, storage, parameterized queries
│   ├── tests/                    # 86 pytest tests (security, WS, rules, reports, notifications, metrics, demo)
│   └── requirements.txt
├── frontend/                     # React dashboard (Vite)
│   └── src/
│       ├── components/
│       │   ├── Layout.jsx        # sidebar, nav, notification bell, demo badge, WS status
│       │   ├── DashboardPage.jsx # SOC metrics KPIs, detection feed, risk trend
│       │   ├── HostDetailPage.jsx# host investigation view
│       │   ├── ReportsPage.jsx   # report generation and inspection
│       │   └── ...
│       ├── api.js                # REST client (reports, notifications, all endpoints)
│       └── useLiveSocket.js      # authenticated WebSocket hook
├── data/                         # SQLite database (runtime)
├── docs/                         # architecture, API, detection matrix, license inventory
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── LICENSE_INVENTORY.md
```

---

## Quick Start — Development

### Prerequisites
- Python 3.11+
- Node.js 18+
- PowerShell (Windows) or bash (Linux/macOS)

### 1. Backend

```bash
cd "AI Sentinel/backend"
python -m venv ..\.venv
..\..\.venv\Scripts\Activate.ps1    # Windows  |  source ../../venv/bin/activate (Linux/macOS)
pip install -r requirements.txt
```

Create `.env` from the template:
```bash
Copy-Item ..\..\.env.example ..\..\.env    # edit with your secrets
```

Key settings for first run:
- `SENTINEL_AUTH_SECRET` — generate a random secret (required in production)
- `SENTINEL_AGENT_KEY` — shared key for endpoint agents
- `SENTINEL_ADMIN_PASSWORD` — bootstrap admin password (or leave blank for random)
- `SENTINEL_ML_ENABLED=true` — enable anomaly detection

Start the backend:
```bash
uvicorn app.main:app --reload --port 8000
```

On first start the database is created and the `admin` account is bootstrapped.
If `SENTINEL_ADMIN_PASSWORD` is not set, a random password is written to
`backend/bootstrap_admin.txt` — rotate it after first login.

### 2. Frontend

```bash
cd ../frontend
npm install
npm run dev
```

- Dashboard: http://localhost:5173
- API docs: http://localhost:8000/docs
- Public health: http://localhost:8000/api/health
- Readiness probe: http://localhost:8000/api/ready

Vite proxies `/api` and `/ws` to the backend on port 8000, so no CORS
configuration is needed in development.

---

## Quick Start — Production (Docker)

```bash
Copy-Item .env.example .env
# EDIT .env:
#   SENTINEL_AUTH_SECRET = long random value
#   SENTINEL_AGENT_KEY   = shared agent key
#   SENTINEL_ADMIN_PASSWORD = strong admin password

docker compose up --build -d
```

Both API and UI are served from a single container on port 8000.

Data is persisted in the `sentinel-data` Docker volume (survives container
restarts and rebuilds).

---

## Real-Time Event Ingestion

Agents and collectors push normalized events to:

```
POST /api/events/ingest
Authorization: Bearer <token>  |  X-Agent-Key: <shared_key>
```

```json
{
  "events": [{
    "ts": "2026-09-14T12:00:00Z",
    "event_type": "auth.failed_login",
    "source_ip": "203.0.113.50",
    "username": "bob",
    "details": {"reason": "invalid password"}
  }]
}
```

Supported event types: `auth.login`, `auth.failed_login`, `auth.logout`, `process.start`, `file.write`, `file.delete`, `file.rename`, `network.connection`, `network.connection_failed`, `web.request`, `dns.query`, `user.account_change`, `service.stop`, plus `telemetry.system`, `telemetry.network`, `telemetry.process`, `telemetry.disk`, `telemetry.connection` snapshots.

Detection rules are runtime-editable from the **Detection Rules** page —
enable/disable, edit, create, test against stored history, with immutable
version history and rollback. Every change is audit-logged.

---

## Live Dashboard & UI

| Page | What it shows |
|------|---------------|
| Overview | Security score, risk, open incidents, SOC metrics (MTTD/MTTA/MTTR), network throughput, live detection feed, attack categories, trend |
| Live Events | Real-time event stream with severity badges, filterable |
| Alerts | Alert list with severity/status, acknowledgement workflow |
| Incidents | Open/investigating/contained/resolved incidents with risk scores |
| Incident Detail | Evidence timeline, raw events, MITRE tags, analyst notes, response actions, recommended actions, incident report generation |
| Hosts | All monitored hosts with CPU/memory/processes, status, link to investigation |
| Host Investigation | Per-host risk score, alert/incident linkage, CPU/memory sparklines, network activity, event list |
| Detection Rules | Full CRUD, version history, rollback, test-against-history |
| Phishing Analysis | Safe URL analysis (no link-following) |
| Network | Network traffic, connections, top talkers |
| AI Assistant | Grounded SOC assistant (rule-based or LLM-backed) |
| Reports | Generate daily/posture reports, view/inspect/delete, incident reports from detail page |
| System | Pipeline stats, ML model status, agent health, audit log, retention management |

The **sidebar** shows:
- WebSocket connection status (Live / Reconnecting / Offline)
- DEMO banner (visible only when `SENTINEL_DEMO_MODE=true`)
- Notification bell with unread count (polls every 20s, refreshes on window focus)

---

## SOC Response Metrics

All computed from real alert and incident timestamps (no fake values):

| Metric | Meaning |
|--------|---------|
| MTTD | Mean Time to Detect — average `detected_at - event.ts` across all detected events |
| MTTA | Mean Time to Acknowledge — average `acknowledged_at - alert.created_at` across acknowledged alerts |
| MTTR (respond) | Mean Time to Respond — average first response action timestamp per incident |
| MTTR (resolve) | Mean Time to Resolve — average `resolved_at - incident.created_at` across resolved incidents |

Metrics are `null` when no qualifying samples exist (never faked to zero).
Visible on the Overview dashboard and available via `GET /api/overview` → `soc_metrics`.

---

## Reporting

Reports are generated on demand from real persisted data and stored with an audit trail.

| Report Type | Endpoint | Who can generate |
|-------------|----------|------------------|
| Daily SOC Report | `POST /api/reports/daily` | SOC_ANALYST+ |
| Security Posture Report | `POST /api/reports/posture` | SOC_ANALYST+ |
| Incident Report | `POST /api/reports/incident/{id}` | SOC_ANALYST+ |

All authenticated users can view reports; only SECURITY_ENGINEER+ can delete them.
Each report stores: title, period, summary, full content, created_by, created_at.

---

## Notifications

**In-app**: every alert notification is persisted in the `notifications` table.
The frontend polls `GET /api/notifications/unread-count` every 20s and shows an
unread badge on the bell icon. Mark individual or all as read.

**Webhook**: when `SENTINEL_NOTIFY_WEBHOOK_URL` is set, critical (and above)
alerts are POSTed to the URL in the background. The status field honestly
reports `NOT_CONFIGURED` when no URL is present — the system never pretends
the webhook is active when it isn't.

---

## Demo / Simulation Mode

Demo mode is **off by default** (`SENTINEL_DEMO_MODE=false`). When explicitly
enabled:

- All generated events are marked `is_simulated=1` and `source=demo`
- All demo hosts are prefixed `demo-` (e.g. `demo-web-01`)
- All source IPs use RFC 5737 TEST-NET ranges (198.51.100.x, 203.0.113.x)
- A visible **DEMO MODE** banner appears in the sidebar and mobile header
- A `demo.start` audit entry is logged with the host list on startup
- Disabling demo mode immediately stops all generation (no events are created)

Every demo event flows through the **exact same** detection pipeline as real
telemetry, so rules and correlations exercise the full SOC workflow.

---

## Authentication & Authorization

- Passwords: PBKDF2-HMAC-SHA256 (210k iterations, unique salt per user)
- Tokens: HMAC-SHA256 signed with expiry (`SENTINEL_TOKEN_TTL`, default 8h)
- Roles: `ADMIN`, `SOC_ANALYST`, `SECURITY_ENGINEER`, `VIEWER`
- WebSocket auth: `Sec-WebSocket-Protocol: sentinel.<token>` (token in URL rejected)
- Every sensitive action (login, respond, rule changes, alert updates, report generation) is written to the audit log with actor, role, result, and timestamp.

`admin/admin` does not exist and never will. Bootstrap credentials are random
or set via `SENTINEL_ADMIN_PASSWORD`. Rotate after first login.

---

## Readiness & Health Probes

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /api/health` | No | Public load-balancer check: version, database status, demo_mode |
| `GET /api/ready` | No | Kubernetes/Docker readiness: database + pipeline checks, 503 if not ready |
| `GET /api/system/health` | Yes | Full component health: database, pipeline, websocket, telemetry, ML, threat intel, agents, notifications, AI provider |
| `GET /api/system/metrics` | Yes | Pipeline stats, queue depth, agent status, latency SLA, config dump |

---

## Response Engine

Response actions are policy-gated. With `SENTINEL_RESPONSE_DRY_RUN=true`
(default), every action is **recorded but never executed** — safe for
evaluation. Only set to `false` after real integrations are configured.

Available actions: `ALERT_SOC`, `BLOCK_IP`, `ISOLATE_ENDPOINT`,
`PRESERVE_EVIDENCE`, `PROTECT_BACKUPS`, `QUARANTINE_FILE`, `REQUIRE_MFA`,
`REVOKE_SESSIONS`.

---

## Testing

### Backend (86 tests)

```bash
cd backend
# Use the Python environment that has the app installed (here .\.venv, or your own venv/)
.\.venv\Scripts\python.exe -m pytest -q
```

Tests cover:
- Password hashing, token signing, token revocation
- Security hardening (production config guard, XFF trusted proxy, rate limiting)
- Real-time WebSocket authentication and live push
- Phishing → incident correlation
- Detection rules CRUD, version history, rollback, test-against-history
- Latency SLA targets and lifecycle timestamps
- Agent heartbeats and offline detection
- Report generation, listing, and deletion (daily, posture, incident)
- Notification creation, unread counting, mark read, read-all
- SOC metrics (MTTD/MTTA/MTTR) structure and empty-store handling
- Demo mode: disabled-by-default no-op, simulated-event flagging, is_simulated guard
- Readiness probe (`/api/ready`) and component health
- Full API surface coverage

### Frontend build

```bash
cd frontend
npm ci && npm run build
```

### Live E2E smoke (27 checks)

```bash
cd backend
.\.venv\Scripts\python.exe scripts\e2e_smoke.py
```

Requires both backend (:8000) and frontend (:5173) running.

---

## Key Configuration Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SENTINEL_AUTH_SECRET` | *(must be set)* | HMAC secret for token signing |
| `SENTINEL_ADMIN_PASSWORD` | *(random)* | Bootstrap admin password |
| `SENTINEL_AGENT_KEY` | *(must be set)* | Shared key for endpoint agents |
| `SENTINEL_DB_PATH` | `data/sentinel.db` | SQLite storage path |
| `SENTINEL_RETENTION_DAYS` | `30` | Event retention window |
| `SENTINEL_RESPONSE_DRY_RUN` | `true` | Gate destructive response actions |
| `SENTINEL_ML_ENABLED` | `true` | Enable Isolation Forest anomaly detection |
| `SENTINEL_TI_ENABLED` | `false` | Enable threat intelligence lookups |
| `SENTINEL_DEMO_MODE` | `false` | Opt-in simulation mode (clearly labelled in UI) |
| `SENTINEL_DEMO_INTERVAL` | `45` | Seconds between demo batches |
| `SENTINEL_NOTIFY_WEBHOOK_URL` | *(empty)* | External webhook URL; empty = NOT_CONFIGURED |
| `SENTINEL_NOTIFY_MIN_SEVERITY` | `critical` | Minimum severity forwarded to webhook |
| `SENTINEL_LATENCY_TARGET_EVENT_MS` | `2000` | Ingest-to-dashboard latency target |
| `SENTINEL_LATENCY_TARGET_CRITICAL_MS` | `5000` | Critical event latency target |
| `OPENAI_API_KEY` | *(optional)* | LLM key for AI SOC assistant (falls back to rule-based) |

See `.env.example` for the full list with documentation.

---

## License

See `docs/LICENSE_INVENTORY.md` for a full audit of all dependencies. Every
direct dependency uses a permissive license (MIT, BSD-3-Clause, or Apache-2.0).
No copyleft (GPL/AGPL/LGPL) dependencies are present.

---

## Documentation

| File | Contents |
|------|----------|
| `docs/LICENSE_INVENTORY.md` | Full dependency license audit |
| `docs/architecture.md` | System architecture |
| `docs/api.md` | REST API reference |
| `docs/websocket.md` | WebSocket reference |
| `docs/detection_matrix.md` | Detection rules and MITRE mappings |
| `docs/ml_architecture.md` | ML model architecture |
| `docs/incident_response.md` | Incident response workflow |
| `docs/environment_variables.md` | Full env var reference |
| `docs/security_checklist.md` | Production security checklist |
| `docs/audit_report.md` | Security audit report |
| `docs/testing.md` | Testing methodology |
| `docs/roadmap.md` | Feature roadmap |

---

## Support

Report issues at: https://github.com/Akhil-Aids/AI-Sentinel/issues
