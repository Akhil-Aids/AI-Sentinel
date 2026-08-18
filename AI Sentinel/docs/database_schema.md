# AI Sentinel — Database Schema

SQLite (WAL), created by `app/db.py::SCHEMA`. JSON-encoded columns store
structured payloads (`details`, `timeline`, `event_ids`, `evidence`, `mitre`,
`config`, `params`). All writes are parameterized.

## users
| column | type | notes |
|---|---|---|
| id | INTEGER PK | autoincrement |
| username | TEXT UNIQUE | |
| password_hash | TEXT | PBKDF2 `$pbkdf2-sha256$…` |
| role | TEXT | CHECK IN (ADMIN, SOC_ANALYST, SECURITY_ENGINEER, VIEWER) |
| full_name | TEXT | |
| is_active | INTEGER | 0/1 |
| created_at / last_login_at | TEXT | |

## servers
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| hostname | TEXT UNIQUE | |
| ip / os / platform | TEXT | |
| status | TEXT | online/offline/unknown |
| cpu / memory / disk | REAL | latest psutil snapshot |
| processes / uptime | INTEGER/REAL | |
| last_seen_at / created_at | TEXT | |
| tags | TEXT | JSON array |

## events  (indexes: ts, event_type, severity, source_ip, host)
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| event_id | TEXT UNIQUE | generated |
| ts | TEXT | event timestamp |
| source / host / event_type | TEXT | |
| category / severity | TEXT | |
| confidence | REAL | 0–1 |
| risk_score | INTEGER | 0–100 |
| source_ip / dest_ip / port / protocol | TEXT/INTEGER/TEXT | |
| username / target / process / command | TEXT | |
| details | TEXT JSON | normalized feature payload |
| mitre | TEXT JSON | |
| raw | TEXT JSON | original payload |
| ingested_at | TEXT | |

## alerts  (indexes: created_at, severity, group_key)
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| alert_id | TEXT UNIQUE | |
| title / description / severity | TEXT | |
| risk_score | INTEGER | |
| status | TEXT | NEW / … |
| source | TEXT | rule_id |
| event_ids | TEXT JSON | |
| created_at / updated_at | TEXT | |
| assigned_to | TEXT | |
| group_key | TEXT | dedup key `rule|source` |
| feedback | TEXT | TRUE_POSITIVE / FALSE_POSITIVE / BENIGN / NEEDS_INVESTIGATION / '' |

## incidents  (indexes: created_at, status, severity)
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| incident_id | TEXT UNIQUE | |
| title / severity / status | TEXT | status: NEW…FALSE_POSITIVE |
| risk_score / confidence | INTEGER/REAL | |
| category | TEXT | can be `;`-joined multi-family |
| affected_host / affected_user | TEXT | |
| source_ip / dest_ip | TEXT | |
| timeline / event_ids / evidence / mitre / detection_rules / recommended_actions / actions_taken | TEXT JSON | |
| ai_explanation / analyst_notes | TEXT | |
| created_at / updated_at / resolved_at | TEXT | |
| recovery_status | TEXT | |

## incident_events
| column | type |
|---|---|
| incident_id | TEXT |
| event_id | TEXT |
| PRIMARY KEY (incident_id, event_id) | |

## detection_rules
| column | type |
|---|---|
| id | INTEGER PK |
| rule_id | TEXT UNIQUE |
| name / description / category / severity | TEXT |
| enabled | INTEGER |
| mitre / config | TEXT JSON |
| created_at / updated_at | TEXT |

## audit_logs  (index: ts)
| column | type |
|---|---|
| id | INTEGER PK |
| ts / actor / actor_role / action / target / result / ip | TEXT |
| detail | TEXT JSON |

## phishing_scans
| column | type |
|---|---|
| id | INTEGER PK |
| scan_id | TEXT UNIQUE |
| url / verdict / reasons / redirects | TEXT (JSON for lists) |
| risk_score | INTEGER |
| created_at / scanner_ip | TEXT |

## response_actions
| column | type |
|---|---|
| id | INTEGER PK |
| action_id | TEXT UNIQUE |
| ts / incident_id / policy / action / reason / actor / result / rollback | TEXT |
| detail | TEXT JSON |

## threat_intel  (UNIQUE ioc_type + ioc_value)
| column | type |
|---|---|
| id | INTEGER PK |
| ioc_type | TEXT (ip/domain/url/hash) |
| ioc_value | TEXT |
| source / verdict | TEXT |
| first_seen / last_seen | TEXT |

## model_state
| column | type |
|---|---|
| id | INTEGER PK |
| model_name | TEXT |
| version | INTEGER |
| trained_at | TEXT |
| trained_samples | INTEGER |
| params / metrics | TEXT JSON |

## server_stats  (index: hostname + ts DESC)
| column | type |
|---|---|
| id | INTEGER PK |
| hostname / ts | TEXT |
| cpu / memory / disk / network_mbps / requests_per_sec | REAL |
| connections / process_count / bytes_sent / bytes_recv | INTEGER |
