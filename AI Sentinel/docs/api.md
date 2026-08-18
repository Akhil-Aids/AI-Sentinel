# AI Sentinel — REST API Reference

Base URL (dev): `http://localhost:8000/api`
Base URL (prod/single-container): `http://<host>:8000/api`
Interactive docs: `/docs` (Swagger UI).

All routes except `/api/health` and `/api/auth/login` require:
```
Authorization: Bearer <token>
```

## Auth

| Method | Path | Auth | Body / Params | Response |
|---|---|---|---|---|
| POST | `/api/auth/login` | none | `{"username","password"}` | `{token, role, username, expires_in}` |
| GET | `/api/auth/me` | user | – | `{username, role, full_name, is_active, created_at}` |
| POST | `/api/auth/change-password` | user | `{"current_password","new_password"}` | `{status:"ok"}` |
| GET | `/api/auth/users` | SOC_ANALYST+ | – | `{items:[…]}` |
| POST | `/api/auth/users` | ADMIN | `{"username","password","role","full_name"}` | `{id, username, role}` |
| PATCH | `/api/auth/users/{user_id}` | ADMIN | `{role?,full_name?,is_active?,password?}` | `{status:"ok"}` |

Login rate-limited: 10 failures per source IP per 5 minutes → HTTP 429.

## Overview

| Method | Path | Response |
|---|---|---|
| GET | `/api/overview` | SOC overview (see shape below) |

```json
{
  "servers": {"total":1,"online":1,"critical":0,"healthy":1},
  "incidents": {"total":2,"open":1,"by_severity":{"critical":0,"high":1,"medium":1,"low":0}},
  "alerts": {"total":3,"critical":0,"high":2,"medium":1,"low":0,"open":3},
  "events": {"today":210,"last_hour":210,"eps":0.3,"queue_depth":0},
  "risk": {"score":60,"level":"high"},
  "security_score": {"score":87,"level":"good"},
  "attack_categories": {"credential-attack":1},
  "ml": {"enabled":true,"model_loaded":false,"version":0,"trained_samples":0,
         "trained_at":"","contamination":0.05},
  "pipeline": {"eps":0.3,"processed":210,"queue_depth":0,"ws_connections":0,"detections_today":3}
}
```

## Events

| Method | Path | Auth | Body / Params | Response |
|---|---|---|---|---|
| POST | `/api/events/ingest` | user | `{"events":[{…},…]}` | `{accepted, dropped}` |
| POST | `/api/events/ingest/agent` | `X-Agent-Key` header | `{"events":[…]}` | `{accepted, dropped}` |
| GET | `/api/events/` | user | `limit(≤500), event_type, severity, source_ip, host` | `{items:[…]}` |
| GET | `/api/events/{event_id}` | user | – | event object or 404 |

Ingest is **non-blocking**: events are enqueued and processed by background
workers. `accepted` counts enqueued events; detection results appear shortly
after via polling or WebSocket.

Canonical event object:

```json
{
  "event_id": "evt_a1b2…", "ts": "2026-08-16T12:00:00Z", "source": "agent",
  "host": "srv-01", "event_type": "auth.failed_login", "category": "auth",
  "severity": "high", "confidence": 0.9, "risk_score": 45,
  "source_ip": "203.0.113.50", "dest_ip": "", "port": 0, "protocol": "tcp",
  "username": "bob", "target": "", "process": "", "command": "",
  "details": {"reason": "invalid password"}, "mitre": ["T1110"], "ingested_at": "…"
}
```

Supported `event_type` values: `auth.login`, `auth.failed_login`,
`auth.successful_login`, `auth.logout`, `auth.privilege_change`,
`process.created`, `file.created`, `file.modified`, `file.deleted`,
`file.renamed`, `net.connection`, `net.connection_failed`, `web.request`,
`dns.query`, `user.account_change`, `service.stop`, `data.access`, and
telemetry snapshots (`telemetry.snapshot`, `server.metrics`).

## Incidents

| Method | Path | Auth | Body / Params | Response |
|---|---|---|---|---|
| GET | `/api/incidents/` | user | `limit(≤500), status, severity` | `{items:[…]}` |
| GET | `/api/incidents/{incident_id}` | user | – | incident + `_events[]` |
| PATCH | `/api/incidents/{incident_id}` | SOC_ANALYST+ | `{status?, analyst_notes?, recovery_status?}` | updated incident |
| POST | `/api/incidents/{incident_id}/respond` | SECURITY_ENGINEER+ | `{"action","reason"}` | response record |
| GET | `/api/incidents/{incident_id}/actions` | user | – | `{items:[…]}` |
| GET | `/api/incidents/policies/available` | user | – | `{actions:{…}}` |

`status` ∈ `NEW | INVESTIGATING | CONTAINED | RESOLVED | FALSE_POSITIVE`.

Valid `action` values (see `policies/available` for live policy status):
`ALERT_SOC`, `BLOCK_IP`, `ISOLATE_ENDPOINT`, `PRESERVE_EVIDENCE`,
`PROTECT_BACKUPS`, `QUARANTINE_FILE`, `REQUIRE_MFA`, `REVOKE_SESSIONS`.

Response result shape:

```json
{
  "recorded": {"action_id":"ra_…","incident_id":"inc_…","policy":"BLOCK_IP",
               "action":"BLOCK_IP","reason":"…","actor":"admin(ADMIN)",
               "result":"BLOCKED","ts":"…"},
  "status": {"action":"BLOCK_IP","permitted":false,"destructive":true,
             "dry_run":true,"reason":"Blocked: dry-run mode (set SENTINEL_RESPONSE_DRY_RUN=false to enable)"},
  "result": "BLOCKED"
}
```

With `SENTINEL_RESPONSE_DRY_RUN=true` (default) actions are recorded and
blocked, never executed.

## Alerts

| Method | Path | Auth | Body / Params | Response |
|---|---|---|---|---|
| GET | `/api/alerts/` | user | `limit(≤500), severity, status` | `{items:[…]}` |
| PATCH | `/api/alerts/{alert_id}` | SOC_ANALYST+ | `{status?, assigned_to?, feedback?}` | updated alert |

`feedback` ∈ `TRUE_POSITIVE | FALSE_POSITIVE | BENIGN | NEEDS_INVESTIGATION`.

## Rules

| Method | Path | Auth | Body / Params | Response |
|---|---|---|---|---|
| GET | `/api/rules/` | user | – | `{items:[…], categories:{…}}` |
| POST | `/api/rules/reset` | ADMIN | – | `{reset: n}` |
| POST | `/api/rules/{rule_id}/toggle` | ADMIN | – | `{rule_id, enabled}` |
| PUT | `/api/rules/{rule_id}` | ADMIN | `{name?, description?, severity?, enabled?, config?}` | updated rule |

## Phishing

| Method | Path | Auth | Body / Params | Response |
|---|---|---|---|---|
| POST | `/api/phishing/analyze` | user | `{"url"}` | verdict result |
| GET | `/api/phishing/scans` | user | – | `{items:[…]}` |

Analysis is **static and safe** — the URL is never fetched or visited.

```json
{
  "url": "https://paypal-account-verify.info/login",
  "host": "paypal-account-verify.info",
  "verdict": "MALICIOUS", "risk_score": 70, "confidence": 0.85,
  "reasons": ["Look-alike domain of: paypal", "Credential-collection indicators in path/query"],
  "redirects": []
}
```

`verdict` ∈ `SAFE | SUSPICIOUS | MALICIOUS` (thresholds: ≥60 malicious, ≥25 suspicious).

## Network

| Method | Path | Response |
|---|---|---|
| GET | `/api/network/traffic` | `{series:[Mbps…], unit:"Mbps", current, hosts:[…]}` |
| GET | `/api/network/connections` | `{items:[net.connection events]}` |
| GET | `/api/network/servers` | `{items:[server + history[60]]}` |

All values come from real `server_stats` time series collected via psutil.

## Chatbot

| Method | Path | Auth | Body | Response |
|---|---|---|---|---|
| POST | `/api/chatbot/` | user | `{"message"}` | `{question, answer, source:"live-telemetry"}` |

Answers are grounded in live telemetry (risk level, incidents, alerts, server
health, event volume, MITRE techniques, recommended actions) — no LLM API call,
no hallucinated numbers.

## System / Observability

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/api/system/health` | none (public) | `{status, service, version, database, pipeline_started}` |
| GET | `/api/system/metrics` | user | `{storage, pipeline, ml, websocket_clients, queue, config}` |
| GET | `/api/system/audit` | SOC_ANALYST+ | `{items:[audit entries]}` |
| POST | `/api/system/retention/apply` | ADMIN | `{status:"ok", deleted:{…}}` |

## Misc / Public

| Method | Path | Response |
|---|---|---|
| GET | `/api/health` | `{status:"ok", service, version, demo_mode}` |

## HTTP status conventions

- `401` invalid/missing token or credentials
- `403` authenticated but insufficient role
- `404` unknown resource
- `400` invalid payload / unknown enum value
- `409` duplicate username
- `429` login rate limit exceeded
