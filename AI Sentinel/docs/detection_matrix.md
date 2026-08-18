# AI Sentinel — Attack Detection Matrix

| # | Attack family | Detection inputs (real telemetry) | Detection mechanism | Severity | MITRE ATT&CK |
|---|---|---|---|---|---|
| 1 | Phishing | URL/domain/host structure, redirects (never followed), TLD, punycode, userinfo `@`, shorteners, credential keywords, sensitive query params, local TI | Static analyzer (`phishing/analyzer.py`) → SAFE/SUSPICIOUS/MALICIOUS + risk 0–100 | SAFE/SUSPICIOUS/MALICIOUS | T1566 |
| 2 | Brute force | `auth.failed_login` velocity per source IP & accounts (window) | Rule `brute_force_velocity` (≥10 fails/10 min, ≥2 accounts) | high | T1110, T1110.001/003 |
| 3 | Credential stuffing | one account, many source IPs | Rule `distributed_login_attempts` (≥5 IPs) | high | T1110, T1110.004 |
| 4 | Successful login after failures | `auth.successful_login` after `auth.failed_login` burst | Rule `success_after_failures` | high | T1078, T1110 |
| 5 | Web: SQL injection | `web.request` structural patterns | Rule `sql_injection` (pattern prefix `sql`) | high | T1190, T1189 |
| 6 | Web: XSS | `web.request` structural patterns | Rule `xss` (prefix `xss`) | medium | T1059.007, T1189 |
| 7 | Web: command injection | `web.request` structural patterns | Rule `command_injection` (prefix `cmd`) | high | T1059, T1190 |
| 8 | Web: path traversal | `web.request` structural patterns | Rule `path_traversal` (prefix `traversal`) | medium | T1083, T1005 |
| 9 | DDoS / DoS | `web.request` rate per host (baseline-aware, window) | Rule `ddos_request_flood` (≥600 req/min/host) — not CPU-based | high | T1498, T1499 |
| 10 | Malware | `file.created` with suspicious characteristics | Rule `suspicious_executable` | high | T1204, T1059 |
| 11 | Ransomware-like behavior | burst of file create/modify/delete/rename per host | Rule `ransomware_file_burst` (≥20/2 min) → evidence preserved, contain, verify backups | critical | T1486, T1490 |
| 12 | Data exfiltration | outbound `net.connection` volume to a destination | Rule `exfiltration_connection_flood` (≥30/10 min) | high | T1041, T1048 |
| 13 | Exfiltration chain | `data.access` + outbound transfers | Rule `sensitive_data_outbound` (≥10 outbound) | critical | T1005, T1041 |
| 14 | Privilege escalation | `auth.privilege_change`, `user.admin_grant`, elevated `process.created` | Rules `privilege_change`, `privileged_process_creation` | medium | T1548, T1078, T1059 |
| 15 | Port scanning / recon | fan-out of `net.connection` / `net.connection_failed` | Rule `port_scan` (≥15/5 min) | medium | T1046, T1040 |
| 16 | Insider / unusual behavior | successful logins outside working hours | Rule `unusual_login_time` (6–22 default) — single anomaly ≠ verdict, human review required | low | T1078 |
| 17 | Behavioral anomalies | telemetry features (CPU, mem, disk, throughput, req/s, failed logins, connections, suspicious ports) vs learned baseline | Isolation Forest (ML layer) with grounded explanation | medium/high | mapped by incident context |
| 18 | Known-malicious indicators | IP/domain/URL reputation, local IOCs | Threat-intel integration (`threat_intel.py`, optional VT/AbuseIPDB) + local IOC seeding | adds risk bonus | n/a |
| 19 | Malicious URL (phishing) | URL analysis verdicts stored on events | Rule `phishing_malicious` (verdict == MALICIOUS → alert + T1566 incident) | high | T1566 |
| 20 | Generic config-driven rules | any stored event fields / event velocity | API-created rules via predicates `field_equals`, `count_events_gt` (runtime-created; cannot edit code-only rules) | configurable | configurable |

## Rules lifecycle (runtime)

Every rule ships with a version; every change writes an immutable history row
(changed_by, changed_at, snapshot). Operators can **test a rule against stored
history** (no live side effects) and **roll back** to any prior version
(rollback creates a new version). Custom rules may only use the generic
predicates `field_equals` / `count_events_gt`; code-only predicates are guarded.

## Correlation → incident

Related detections merge into one incident when they share source IP, user, or
host within a 6-hour window and are in the same (or related) attack family.
Kill-chain progression weights:

| family | progression |
|---|---|
| credential-attack | 0.4 |
| initial-access | 0.2 |
| web-attack | 0.3 |
| network | 0.25 |
| malware | 0.5 |
| privilege | 0.6 |
| exfiltration | 0.8 |
| ransomware | 0.9 |

Exfiltration and ransomware pull in related families (chain detection). Each
incident records timeline, evidence, MITRE mapping, detection rules, AI
explanation, recommended actions, and response actions taken.

## Honesty guarantees

- No detection is claimed without real telemetry evidence (event store,
  structural patterns, or a trained model with a real baseline).
- TI is only consulted for actual indicators present in events.
- ML anomalies include only |z|≥2 features in the explanation, grounded in the
  training baseline; never fabricated reasons.
