# AI Sentinel — Environment Variables

All settings come from environment variables loaded via `.env` (project root)
using python-dotenv. Copy `.env.example` to `.env`. **Never commit `.env`.**

## Runtime

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_ENV` | `development` | `development` / `production` |
| `SENTINEL_DEBUG` | `false` | FastAPI debug mode |

## Auth & secrets

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_AUTH_SECRET` | `development-only-change-me` | HMAC secret for token signing. **Must be set to a long random value in production.** Generate: `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `SENTINEL_TOKEN_TTL` | `28800` | Token lifetime in seconds (8 h) |
| `SENTINEL_ADMIN_PASSWORD` | empty | Bootstrap admin password; if empty a random one is generated and written to `backend/bootstrap_admin.txt` |
| `SENTINEL_AGENT_KEY` | empty | Shared key for `POST /api/events/ingest/agent` (`X-Agent-Key` header) |

## Storage

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_DB_PATH` | `<workspace>/data/sentinel.db` | SQLite file path |
| `SENTINEL_RETENTION_DAYS` | `30` | Raw event retention window (purged by retention job) |

## Pipeline

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_WORKERS` | `2` | Number of detection workers |
| `SENTINEL_QUEUE_MAXSIZE` | `20000` | In-process queue capacity (backpressure) |

## ML

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_MODEL_DIR` | `<workspace>/backend/models` | Model + scaler persistence |
| `SENTINEL_ML_ENABLED` | `true` | Enable Isolation Forest anomaly layer |
| `SENTINEL_ML_RETRAIN_MIN_SAMPLES` | `200` | New samples required before retraining |
| `SENTINEL_ML_CONTAMINATION` | `0.05` | Assumed anomaly fraction |

## Phishing

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_PHISHING_ENABLED` | `true` | Enable URL analysis |

## Threat intelligence (optional)

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_TI_ENABLED` | `false` | Enable external TI lookups |
| `VIRUSTOTAL_API_KEY` | empty | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | empty | AbuseIPDB API key |

Local IOCs (`app/threat_intel.py`, `seed_local_iocs`) work without any keys.

## Response engine

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_RESPONSE_DRY_RUN` | `true` | When true, destructive response actions are recorded but **blocked** |

## Frontend / CORS

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated allowed origins (dev Vite). Not needed when served same-origin |

## Monitoring

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_MONITOR_DIRS` | `<workspace>/backend` | Semicolon-separated directories monitored for file events (used to build file-change detections) |

## Demo mode

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_DEMO_MODE` | `false` | Explicit, clearly-labelled simulation mode. Never defaults on; simulated data never enters the production store when off |
