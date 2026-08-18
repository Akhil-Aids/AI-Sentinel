# AI Sentinel — Architecture

## 1. High-level architecture diagram

```
                  COMPANY INFRASTRUCTURE
   (servers, applications, databases, employees, APIs, endpoints)
                              │  psutil agents / event shippers
                              ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │                      EVENT INGESTION LAYER                        │
   │   POST /api/events/ingest        (user bearer token)              │
   │   POST /api/events/ingest/agent  (X-Agent-Key shared secret)      │
   │   Telemetry collector (psutil) samples host every 15 s            │
   └───────────────────────────────────────────────────────────────────┘
                              │  non-blocking enqueue
                              ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │                MESSAGE QUEUE (asyncio.Queue, backpressure)        │
   └───────────────────────────────────────────────────────────────────┘
                              ▼  workers (asyncio.to_thread)
   ┌───────────────────────────────────────────────────────────────────┐
   │   EVENT NORMALIZATION  (app/pipeline/normalize.py)                │
   │   PERSISTENCE          (app/db.py, SQLite WAL)                    │
   │   DETECTION ENGINE     (app/engines/)                             │
   │      ├─ Rule engine: 16 configurable rules (brute force, SQLi,    │
   │      │   XSS, cmd injection, path traversal, ransomware burst,    │
   │      │   exfiltration, DDoS, port scan, privilege, …)             │
   │      ├─ Structural analyzers (web.request patterns)               │
   │      └─ ML anomaly layer (Isolation Forest, trained on            │
   │           accumulated historical telemetry)                       │
   │   RISK ENGINE  (app/risk.py)  0–100, severity+confidence+asset+   │
   │       progression+TI bonus                                        │
   │   THREAT INTELLIGENCE (app/threat_intel.py, optional VT/AbuseIPDB)│
   │   CORRELATION   (app/correlate.py → incidents, MITRE, timeline)   │
   │   ALERT DEDUP   (group_key, 30-min window)                        │
   │   RESPONSE ENGINE (app/response.py, policy-gated, dry-run default)│
   └───────────────────────────────────────────────────────────────────┘
                              ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │   SQLITE PERSISTENCE  (events, alerts, incidents, audit, IOCs,    │
   │                         model_state, server_stats, phishing_scans)│
   └───────────────────────────────────────────────────────────────────┘
                              ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │   WEBSOCKET PUSH  /ws/events?token=…                             │
   │      hello | stats | event | detection | alert | incident        │
   └───────────────────────────────────────────────────────────────────┘
                              ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │   REACT DASHBOARD (Vite)  overview, live stream, incidents,      │
   │     alerts, rules, phishing, network, assistant, system          │
   └───────────────────────────────────────────────────────────────────┘
```

## 2. Queue technology decision

Single-node deployment uses an **in-process `asyncio.Queue`**:

- Non-blocking ingestion (producer `put_nowait`, worker coroutines).
- Backpressure via `maxsize` (`SENTINEL_QUEUE_MAXSIZE`); overflow is audited
  and dropped rather than blocking the API.
- Ordering per worker and thread-safe processing via `asyncio.to_thread`.
- Zero external infrastructure → simplest correct starting point.

The pipeline is encapsulated in `app/pipeline/EventPipeline`. Callers only
call `pipeline.ingest()`; swapping the transport for Redis Streams / Kafka /
RabbitMQ for multi-node scale requires no caller changes.

## 3. Event flow (per event)

1. `pipeline.ingest(raw)` → queue.
2. Worker: `normalize_raw()` → canonical event; `db.save_event()`.
3. Telemetry samples are captured for ML training (never the live snapshot
   loop); `needs_retrain()` gates retraining on ≥ `SENTINEL_ML_RETRAIN_MIN_SAMPLES`.
4. `detection_engine.analyze()` → rule detections + ML anomaly (if model).
5. Risk scored; threat-intel bonus added.
6. Alert dedup by `group_key` (rule + source) within 30 minutes; otherwise a
   new alert is persisted.
7. `correlator.correlate()` merges into an open incident (same source/user/host,
   6-hour window, progression-aware) or creates a new incident with MITRE
   mapping, timeline, evidence, recommended actions.
8. `_broadcast()` schedules a WebSocket push on the main loop via
   `asyncio.run_coroutine_threadsafe` (thread-safe).
9. Audit log written.

## 4. Folder structure

```
AI Sentinel/
├── backend/
│   ├── app/
│   │   ├── main.py              FastAPI app, /ws/events, static hosting
│   │   ├── core/
│   │   │   ├── config.py        env-driven settings
│   │   │   ├── security.py      PBKDF2 hashing, HMAC tokens, RBAC
│   │   │   └── deps.py          auth dependencies
│   │   ├── pipeline/
│   │   │   ├── __init__.py      EventPipeline (workers, alert dedup, WS)
│   │   │   └── normalize.py     event canonicalization
│   │   ├── engines/
│   │   │   ├── __init__.py      detection engine assembly
│   │   │   ├── rules.py         16 rules + predicates + defaults
│   │   │   └── window.py        sliding-window SQL queries
│   │   ├── ml/
│   │   │   └── anomaly.py       Isolation Forest + scaler + explanations
│   │   ├── phishing/
│   │   │   └── analyzer.py      static, safe URL analysis
│   │   ├── telemetry/
│   │   │   ├── collector.py     15s psutil loop
│   │   │   └── system_monitor.py  real metrics collectors
│   │   ├── services/
│   │   │   └── ws_manager.py    authenticated WS broadcast
│   │   ├── routes/              REST routers (auth, overview, events,
│   │   │                         incidents, alerts, network, rules,
│   │   │                         phishing, chatbot, system)
│   │   ├── threat_intel.py      optional TI integration + local IOCs
│   │   ├── risk.py              0–100 risk engine
│   │   ├── correlate.py         incident correlation
│   │   ├── response.py          policy-gated response engine
│   │   ├── db.py                SQLite schema/queries
│   │   └── botsummarizer.py     (see chatbot routes) grounded answers
│   └── tests/                   pytest suite
├── frontend/
│   ├── src/
│   │   ├── api.js               typed API client (relative /api)
│   │   ├── App.jsx              router
│   │   ├── components/          Layout, ui, Dashboard, Events, Alerts,
│   │   │                         Incidents, IncidentDetail, Rules,
│   │   │                         Phishing, Network, Assistant, System,
│   │   │                         Login
│   │   └── main.jsx
│   ├── vite.config.js           dev proxy /api + /ws → :8000
│   └── package.json
├── data/                        SQLite (created at runtime)
├── Dockerfile                   multi-stage build
├── docker-compose.yml
├── .env.example
└── README.md
```

## 5. List of modified files (this milestone)

- `backend/app/core/security.py` — fixed PBKDF2 format (`$pbkdf2-sha256$iter$salt$digest$`, 6-part parse), token signing/verify.
- `backend/app/main.py` — WS loop fix + static hosting; startup order.
- `backend/app/pipeline/__init__.py` — worker detection, `_det_lock` (incident race), `ev = db.save_event(ev)` (event_id propagation), alert dedup (`group_key`), thread-safe `_broadcast`.
- `backend/app/correlate.py` — `risk_score` param, em-dash titles, risk floor.
- `backend/app/engines/window.py` — fixed clauses/params unpacking bug.
- `backend/app/engines/rules.py` — 16 default rules, predicates, categories.
- `backend/app/ml/anomaly.py` — `new_sample_id()`, fixed collect_sample.
- `backend/app/telemetry/collector.py` — unique `telemetry_…` event_ids.
- `backend/app/db.py` — alerts `group_key` column/index, dedup helpers, `timedelta`.
- `backend/app/routes/*.py` — full REST surface.
- `backend/requirements.txt` — added pytest, httpx (dev).
- `frontend/**` — full dashboard rewrite (see section 6).
- `.env.example`, `README.md`, `Dockerfile`, `docker-compose.yml`, `.dockerignore`.

## 6. List of newly created files

- `frontend/src/api.js`, `App.jsx`, `components/{Layout,ui,DashboardPage,EventsPage,AlertsPage,IncidentsPage,IncidentDetailPage,RulesPage,PhishingPage,NetworkPage,AssistantPage,SystemPage,LoginPage}.jsx`
- `backend/tests/{conftest,test_security,test_detection,test_phishing,test_api}.py`
- `Dockerfile`, `docker-compose.yml`, `.dockerignore`
- `docs/*` (this documentation set)
