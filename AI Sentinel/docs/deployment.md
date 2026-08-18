# AI Sentinel — Deployment Instructions

## Development (local)

### Prerequisites
- Python 3.11+ (tested on 3.13)
- Node.js 18+

### Backend
```powershell
cd backend
python -m venv ..\.venv
..\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd ..
Copy-Item .env.example .env     # then set secrets
cd backend
uvicorn app.main:app --reload --port 8000
```

First run creates `data/sentinel.db` and the bootstrap `admin` account. If
`SENTINEL_ADMIN_PASSWORD` is unset, the generated password is written to
`backend/bootstrap_admin.txt` (rotate after first login).

### Frontend
```powershell
cd frontend
npm install
npm run dev          # http://localhost:5173 (proxies /api and /ws to :8000)
```

### Health checks
- http://localhost:8000/api/health
- http://localhost:8000/docs (Swagger)

## Production (Docker Compose — recommended)

```powershell
Copy-Item .env.example .env
# EDIT .env:
#   SENTINEL_AUTH_SECRET=<long random value, e.g. from secrets.token_urlsafe(48)>
#   SENTINEL_ADMIN_PASSWORD=<strong password>
docker compose up --build -d
```

- Single container on `:8000` serves the built React app **and** the API.
- SQLite is persisted in the `sentinel-data` volume (survives rebuilds).
- Healthcheck polls `/api/health`; container restarts on failure
  (`restart: unless-stopped`).

## Configuration reference

See `docs/environment_variables.md` for the full list. Minimum for production:

| Variable | Required | Notes |
|---|---|---|
| `SENTINEL_AUTH_SECRET` | yes | HMAC token secret; must be unique/strong |
| `SENTINEL_ADMIN_PASSWORD` | recommended | else a random one is generated & written to file |
| `SENTINEL_AGENT_KEY` | if agents used | shared secret for `/ingest/agent` |
| `SENTINEL_DB_PATH` | container default `/app/data/sentinel.db` | volume-backed |
| `SENTINEL_RESPONSE_DRY_RUN` | default true | set false only with real integrations |

## Scaling path

- The event pipeline is isolated in `EventPipeline.ingest()`; replacing the
  in-process queue with Redis Streams / Kafka / RabbitMQ enables multiple
  detection workers and agents without caller changes.
- Deploy behind a load balancer / reverse proxy terminating TLS, with
  `SENTINEL_CORS_ORIGINS` set to the public origin(s). WebSocket upgrades must
  be forwarded (`/ws`).

## Upgrading

The SQLite schema is created with `CREATE TABLE IF NOT EXISTS` and additive
migrations. On upgrade, restart the container; new tables/columns are created
automatically. Back up `data/sentinel.db` (or the `sentinel-data` volume) and
`backend/models/` before major upgrades.
