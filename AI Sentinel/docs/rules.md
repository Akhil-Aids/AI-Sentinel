# AI Sentinel — Detection Rule Reference

Rules live in `backend/app/engines/rules.py` and are stored in the
`detection_rules` table. They can be toggled, re-configured, and reset from the
Rules page / `/api/rules/` without code changes. Enabled rules are cached for
10 s and re-read from the database.

Predicate signature: `(ev, cfg) -> bool`. A detection fires when the predicate
returns true; it is scored, alerted (with dedup), and correlated into an
incident.

## Default rules (16)

| rule_id | Name | Category | Severity | MITRE | Default config | Fires when |
|---|---|---|---|---|---|---|
| `brute_force_velocity` | Brute force: excessive failed logins from one source | credential-attack | high | T1110, T1110.001, T1110.003 | `window=10m, min_failures=10, unique_accounts≥2` | ≥10 `auth.failed_login` from one source IP touching ≥2 accounts in 10 min |
| `distributed_login_attempts` | Distributed login attempts against one account | credential-attack | high | T1110, T1110.004 | `window=15m, min_sources=5` | one account receives failed logins from ≥5 distinct IPs |
| `success_after_failures` | Successful login after repeated failures | credential-attack | high | T1078, T1110 | `window=30m, min_failures=5` | successful login for a user/source with ≥5 prior failures |
| `port_scan` | Port scanning / host discovery | network | medium | T1046, T1040 | `window=5m, min_connections=15` | ≥15 `net.connection`/`net.connection_failed` from one source |
| `sql_injection` | SQL injection pattern in request | web-attack | high | T1190, T1189 | – | `web.request` with structural `matched_pattern` starting `sql` |
| `xss` | Cross-site scripting pattern in request | web-attack | medium | T1059.007, T1189 | – | `web.request` with pattern starting `xss` |
| `command_injection` | Command injection pattern in request | web-attack | high | T1059, T1190 | – | `web.request` with pattern starting `cmd` |
| `path_traversal` | Path traversal pattern in request | web-attack | medium | T1083, T1005 | – | `web.request` with pattern starting `traversal` |
| `ddos_request_flood` | Request flood against a host | dos | high | T1498, T1499 | `window=1m, threshold=600` | ≥600 `web.request` for one host in 1 min |
| `suspicious_executable` | Suspicious executable created | malware | high | T1204, T1059 | – | `file.created` with `details.suspicious=true` |
| `ransomware_file_burst` | Ransomware-like file modification burst | ransomware | critical | T1486, T1490 | `window=2m, min_changes=20` | ≥20 file create/modify/delete/rename on one host in 2 min |
| `exfiltration_connection_flood` | Data exfiltration: connection flood to external host | exfiltration | high | T1041, T1048 | `window=10m, min_connections=30` | ≥30 `net.connection` to one destination IP |
| `sensitive_data_outbound` | Sensitive data access followed by outbound transfers | exfiltration | critical | T1005, T1041 | `window=15m, min_outbound=10` | `data.access` by a user with ≥10 outbound connections |
| `privilege_change` | Privilege change | privilege | medium | T1078, T1548 | – | `auth.privilege_change` or `user.admin_grant` |
| `privileged_process_creation` | Privileged process creation | privilege | medium | T1548, T1059 | – | `process.created` with `details.elevated=true` |
| `unusual_login_time` | Login outside normal working hours | insider | low | T1078 | `start=6, end=22` | successful login whose hour is outside the window |

## Rule categories

`credential-attack`, `network`, `web-attack`, `dos`, `malware`, `ransomware`,
`exfiltration`, `privilege`, `insider`, `generic`.

## Configuring rules

```json
PUT /api/rules/{rule_id}
{
  "name": "…", "description": "…", "severity": "critical",
  "enabled": true,
  "config": {"window_minutes": 10, "min_failures": 8, "unique_accounts_threshold": 2}
}
```

Toggle: `POST /api/rules/{rule_id}/toggle`. Reset to defaults:
`POST /api/rules/reset`.

## Severity → risk floor

Detections are floored by severity before correlation:

| severity | min risk |
|---|---|
| low | 20 |
| medium | 40 |
| high | 60 |
| critical | 80 |
