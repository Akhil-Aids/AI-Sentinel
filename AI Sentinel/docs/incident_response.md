# AI Sentinel — Incident-Response Workflow

## Lifecycle

```
NEW ──► INVESTIGATING ──► CONTAINED ──► RESOLVED
  \         │                  │
   \        └──► FALSE_POSITIVE (any stage)
    └──► FALSE_POSITIVE
```

Status transitions are set by analysts via `PATCH /api/incidents/{id}`
(SOC_ANALYST or higher).

## 1. Detection & correlation

The pipeline (rule / structural / ML / TI) produces a detection, which is
scored, deduped into an alert, and correlated into an incident. Dedup collapses
repeated firings of the same rule against the same attacker/asset into one open
alert (`group_key = rule|source`, 30-min window), and concurrent workers cannot
double-create incidents (pipeline-level lock). WebSocket clients receive
`detection` / `alert` / `incident` pushes in real time.

## 2. Triage (analyst)

Incident detail provides:

- **Timeline** (`timeline[]`): each correlated event with time, type, rule.
- **Evidence** (`evidence[]`): event snapshots (details preserved).
- **MITRE ATT&CK** (`mitre[]`): assigned only when the triggering rule carried
  sufficient evidence.
- **AI explanation** (`ai_explanation`): grounded, from the ML baseline.
- **Detection rules** (`detection_rules[]`): which rules fired.
- **Recommended actions** (`recommended_actions[]`): category-specific.

Analyst marks alerts `TRUE_POSITIVE | FALSE_POSITIVE | BENIGN |
NEEDS_INVESTIGATION` (feedback used for future tuning — never auto-learned).

## 3. Response

Available actions (gated by `response_engine.policy_status`, dry-run by
default):

| Action | Policy gate | Notes |
|---|---|---|
| `ALERT_SOC` | always permitted | non-destructive |
| `PRESERVE_EVIDENCE` | always permitted | non-destructive |
| `PROTECT_BACKUPS` | always permitted | non-destructive |
| `REQUIRE_MFA` | permitted unless dry-run | admin policy |
| `BLOCK_IP` | dry-run: blocked | destructive |
| `ISOLATE_ENDPOINT` | dry-run: blocked | destructive |
| `REVOKE_SESSIONS` | dry-run: blocked | destructive |
| `QUARANTINE_FILE` | dry-run: blocked | destructive |

Every execution is recorded in `response_actions` with policy, actor,
timestamp, result, detail, and rollback plan. With
`SENTINEL_RESPONSE_DRY_RUN=true` nothing is actually executed.

## 4. Containment & recovery

For ransomware/exfiltration incidents the workflow emphasizes:
contain host → preserve evidence → verify backups → enable snapshot protection
→ notify response team → prepare recovery guidance. `recovery_status` field
tracks recovery state.

## 5. Resolution

Analyst sets status to `RESOLVED` (or `FALSE_POSITIVE`), adds `analyst_notes`,
and records `recovery_status`. The incident remains searchable in the store;
retention applies only to raw events after `SENTINEL_RETENTION_DAYS`.

## Audit trail

All sensitive operations (login, alert update, incident update, response
action, rule changes, user management, retention) are written to `audit_logs`
with actor, role, action, target, IP, result, and detail.
