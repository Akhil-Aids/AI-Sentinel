# AI Sentinel — Security Audit Report

Audit date: 2026-08-16 · Status per control: **PASS** (tested), **PARTIAL** (present, needs
deployment-specific verification), **FAIL** (gap). Primary evidence: `tests/test_security_hardening.py`,
`tests/test_realtime_ws.py`, live E2E (`backend/scripts/e2e_smoke.py`).

## Identity & authentication

| Control | Status | Evidence / notes |
|---|---|---|
| Password hashing PBKDF2-HMAC-SHA256, 210k iterations, unique salt | PASS | `core/security.py`; hash roundtrip tests |
| No default credentials; random or env bootstrap password, audited | PASS | `auth.bootstrap_admin` audit; bootstrap file is random when env empty |
| Login rate limiting 10/IP/5 min → 429 | PASS | `test_security_hardening.py`; in-memory `_LOGIN_WINDOWS` (single-instance only) |
| HMAC-signed expiring tokens (`sub`, `role`, `iat`, `exp`, `jti`) | PASS | tamper/expiry rejection tests |
| Token revocation when user disabled | PASS | `_user_cache`; `test_disabled_user_token_revoked` |
| `SENTINEL_AUTH_SECRET` strong value | PASS | `.env` rotated to 48-byte URL-safe random; prod guard rejects known-dev default |

## Authorization (RBAC)

| Control | Status | Evidence / notes |
|---|---|---|
| VIEWER read-only: ingest/analyze/rules blocked | PASS | `test_viewer_cannot_ingest_or_analyze…` |
| SOC_ANALYST: alert feedback, incident updates, audit read | PASS | route dependencies + API tests |
| SECURITY_ENGINEER: response actions | PASS | `incidents.py` dependency |
| ADMIN: user management, rules, retention | PASS | auth user routes, rules routes |
| Sensitive actions audited (actor, role, action, target, IP, result) | PASS | E2E audit assertions |

## API & transport

| Control | Status | Evidence / notes |
|---|---|---|
| All endpoints require auth except `/api/health`, `/api/auth/login` | PASS | dependency wiring; security tests |
| Pydantic input validation incl. batch limit ≤ 1000 | PASS | `test_batch_limit…`, malformed-event rejection |
| Parameterized SQL (no string-built queries) | PASS | `db.py` uses bound params throughout |
| Trusted-proxy-aware client IP; XFF ignored by default | PASS | `test_forwarded_for…`; `core/deps.py` |
| Alert + incident status enums validated (400 on invalid) | PASS | security tests; `VALID_ALERT_STATUSES` |
| Response actions policy-gated + dry-run safe | PASS | E2E: destructive → BLOCKED; non-destructive → SUCCESS |
| WebSocket requires valid token; close 4401 on bad token | PASS | `test_realtime_ws.py`; subprotocol auth |
| Static file serving safe against path traversal | PASS | `is_relative_to` guard + SPA fallback |

## Data protection

| Control | Status | Evidence / notes |
|---|---|---|
| SQLite WAL persistence across restarts | PASS | restart-persistence test; live restart smoke |
| Retention policy with audit | PARTIAL | endpoint tested for shape; apply not run against live data |
| TLS / WSS in production | PARTIAL | delegated to reverse proxy (documented); no bundled cert |
| No secrets in frontend; `/api` relative base URL | PASS | code review + build |

## Threat intel & integrations

| Control | Status | Evidence / notes |
|---|---|---|
| TI keys env-only, optional, off by default | PASS | `SENTINEL_TI_ENABLED=false`; no keys in repo |
| Phishing analyzer never fetches URLs | PASS | static analyzer; `redirects` always empty by design |

## Secrets hygiene

| Control | Status | Evidence / notes |
|---|---|---|
| `.env` gitignored; `.env.example` contains no real secrets | PASS | repo check |
| No hard-coded passwords/tokens in repository | PASS | agent key/AUTH_SECRET only in local `.env`; test fixtures use `test-agent-key-123` |
| Prior leaked key rotated | PASS | `SENTINEL_AUTH_SECRET` regenerated this session |

## Operational posture

| Control | Status | Evidence / notes |
|---|---|---|
| Demo mode explicit and OFF by default | PASS | `SENTINEL_DEMO_MODE=false` |
| Observability: health, metrics, audit, WS metrics | PASS | E2E assertions |
| Non-interactive containers + healthcheck | PASS | Dockerfile/compose healthcheck |

## Residual risks (accepted for this milestone)

1. **In-memory rate limiter & queue** — not horizontally scalable; documented.
2. **Audit log not cryptographically tamper-evident** — append-only in SQLite only.
3. **No MFA enforcement** — token architecture is MFA-ready but enrollment absent.
4. **No `tenant_id`** — single-tenant appliance.
5. **Bootstrap admin password on disk** (`backend/bootstrap_admin.txt`) until rotated.
