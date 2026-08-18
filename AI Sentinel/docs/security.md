# AI Sentinel — Security Checklist

Verified: 2026-08-16 (see `AUDIT_REPORT.md` for the full audit with evidence).

## Identity & authentication

- [x] Password hashing: PBKDF2-HMAC-SHA256, 210,000 iterations, unique 16-byte
      salt per password (`core/security.py`).
- [x] No default credentials — `admin`/`admin` does not exist; bootstrap
      password is random or env-supplied and audited.
- [x] Login rate limiting: 10 failures/IP/5 min → HTTP 429.
- [x] Tokens: HMAC-SHA256 signed, expiring (`SENTINEL_TOKEN_TTL`), include
      `sub`, `role`, `iat`, `exp`, `jti`. Tampering/expiry rejected with 401.
- [x] Token revocation on user disable (cached user status).
- [x] `SENTINEL_AUTH_SECRET` set to a strong random value in production.

## Authorization (RBAC)

- [x] Roles enforced via dependencies (`core/deps.py`):
  - `VIEWER`: read-only dashboard.
  - `SOC_ANALYST`: alert feedback, incident updates, audit read.
  - `SECURITY_ENGINEER`: response actions.
  - `ADMIN`: user management, rules, retention, reset.
- [x] Sensitive actions audited with actor, role, action, target, IP, result.

## API security

- [x] All endpoints (except `/api/health`, `/api/auth/login`) require auth.
- [x] Input validation via Pydantic (lengths, patterns, enums, batch limit).
- [x] Parameterized SQL everywhere (`db.py`) — no string-built queries.
- [x] Response actions gated by policy + dry-run; no destructive action
      executes without `SENTINEL_RESPONSE_DRY_RUN=false` and an approved policy.
- [x] Static file serving protects against path traversal
      (`is_relative_to` check + SPA fallback).
- [x] WebSocket requires a valid token (close code 4401 otherwise).
- [x] Trusted-proxy-aware client IP; `X-Forwarded-For` ignored without a
      trusted proxy (no spoofing of the rate-limit key).
- [x] Alert and incident status fields validated (invalid → 400).

## Frontend security

- [x] No API keys / secrets in frontend code; all backend calls are
      server-authenticated.
- [x] Relative `/api` base URL (no hard-coded hostnames) — works behind proxy.
- [x] Secrets stored only in `.env` (backend) / environment.

## Data protection

- [x] SQLite persistence (WAL) — data survives restarts; no wipe on boot.
- [x] Retention policy (`SENTINEL_RETENTION_DAYS`) with audit on apply.
- [ ] TLS required in production (reverse proxy / WSS); WebSocket `wss://`.
- [x] Backups: volume-backed DB in Docker (`sentinel-data`).

## Threat intelligence & integrations

- [x] TI API keys only in env vars, never in code or frontend.
- [x] Phishing analyzer is static; it never fetches or executes URLs.

## Secrets hygiene

- [x] `.env` in `.gitignore`; `.env.example` carries no real secrets.
- [x] No hard-coded passwords, tokens, or DB credentials in the repository.
- [x] `SENTINEL_AUTH_SECRET` regenerated to a strong random value (this session).

## Operational

- [x] `SENTINEL_DEMO_MODE` off by default; simulated data clearly labelled.
- [x] Observability: `/api/system/health`, `/api/system/metrics`, audit log,
      WS connection metrics, agent heartbeats.
- [x] Containers run non-interactively; healthcheck on `/api/health`;
      `restart: unless-stopped`.
