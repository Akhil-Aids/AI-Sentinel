"""SQLite persistence for AI Sentinel.

All security data is stored durably across restarts (no in-memory-only storage).
Indexes are created for high-volume event/alert/incident queries.
Thread-safety: a single module-level connection is guarded by a lock; FastAPI
runs routes in a thread pool, and a short-lived write lock is acceptable for a
single-node deployment.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from app.core.config import settings

DB_DIR = settings.DB_PATH.parent

_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def get_connection() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        DB_DIR.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(str(settings.DB_PATH), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
        init_schema()
    return _conn


@contextmanager
def db() -> sqlite3.Connection:
    conn = get_connection()
    with _lock:
        yield conn
        conn.commit()


def _json(value) -> str:
    return json.dumps(value, default=str)


def _loads(value, default=None):
    if value is None:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('ADMIN','SOC_ANALYST','SECURITY_ENGINEER','VIEWER')),
    full_name TEXT DEFAULT '',
    is_active INTEGER DEFAULT 1,
    mfa_secret TEXT DEFAULT '',
    mfa_enabled INTEGER DEFAULT 0,
    mfa_confirmed_at TEXT,
    created_at TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL UNIQUE,
    ip TEXT DEFAULT '',
    os TEXT DEFAULT '',
    platform TEXT DEFAULT '',
    status TEXT DEFAULT 'unknown',
    cpu REAL DEFAULT 0,
    memory REAL DEFAULT 0,
    disk REAL DEFAULT 0,
    processes INTEGER DEFAULT 0,
    uptime REAL DEFAULT 0,
    last_seen_at TEXT,
    environment TEXT DEFAULT '',
    agent_id TEXT DEFAULT '',
    last_heartbeat_at TEXT,
    tags TEXT DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL UNIQUE,
    hostname TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    os TEXT DEFAULT '',
    environment TEXT DEFAULT '',
    version TEXT DEFAULT '',
    status TEXT DEFAULT 'UNKNOWN',
    last_heartbeat_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    ts TEXT NOT NULL,
    source TEXT DEFAULT 'system',
    source_type TEXT DEFAULT 'telemetry',
    host TEXT DEFAULT '',
    environment TEXT DEFAULT '',
    asset_id TEXT DEFAULT '',
    is_simulated INTEGER DEFAULT 0,
    event_type TEXT NOT NULL,
    category TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',
    confidence REAL DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    source_ip TEXT DEFAULT '',
    dest_ip TEXT DEFAULT '',
    port INTEGER DEFAULT 0,
    protocol TEXT DEFAULT '',
    username TEXT DEFAULT '',
    target TEXT DEFAULT '',
    process TEXT DEFAULT '',
    command TEXT DEFAULT '',
    details TEXT DEFAULT '{}',
    mitre TEXT DEFAULT '[]',
    raw TEXT DEFAULT '{}',
    ingested_at TEXT NOT NULL,
    normalized_at TEXT,
    processed_at TEXT,
    detected_at TEXT,
    correlated_at TEXT,
    alert_created_at TEXT,
    incident_created_at TEXT,
    dashboard_delivered_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_src ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0,
    status TEXT DEFAULT 'NEW',
    source TEXT DEFAULT '',
    event_ids TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT,
    assigned_to TEXT DEFAULT '',
    group_key TEXT DEFAULT '',
    feedback TEXT DEFAULT ''   -- TRUE_POSITIVE | FALSE_POSITIVE | BENIGN | NEEDS_INVESTIGATION | ''
);

CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_group ON alerts(group_key);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT DEFAULT 'NEW',
    risk_score INTEGER DEFAULT 0,
    confidence REAL DEFAULT 0,
    category TEXT DEFAULT '',
    affected_host TEXT DEFAULT '',
    affected_user TEXT DEFAULT '',
    source_ip TEXT DEFAULT '',
    dest_ip TEXT DEFAULT '',
    timeline TEXT DEFAULT '[]',
    event_ids TEXT DEFAULT '[]',
    evidence TEXT DEFAULT '[]',
    mitre TEXT DEFAULT '[]',
    ai_explanation TEXT DEFAULT '',
    detection_rules TEXT DEFAULT '[]',
    recommended_actions TEXT DEFAULT '[]',
    actions_taken TEXT DEFAULT '[]',
    analyst_notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT,
    resolved_at TEXT,
    recovery_status TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    PRIMARY KEY (incident_id, event_id)
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    category TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    severity TEXT DEFAULT 'medium',
    mitre TEXT DEFAULT '[]',
    config TEXT DEFAULT '{}',
    version INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS rule_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    action TEXT DEFAULT 'update',
    snapshot TEXT DEFAULT '{}',
    changed_by TEXT DEFAULT '',
    changed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    actor_role TEXT DEFAULT '',
    action TEXT NOT NULL,
    target TEXT DEFAULT '',
    result TEXT DEFAULT 'SUCCESS',
    ip TEXT DEFAULT '',
    detail TEXT DEFAULT '{}',
    prev_hash TEXT DEFAULT '',
    record_hash TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts DESC);

CREATE TABLE IF NOT EXISTS phishing_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    verdict TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0,
    reasons TEXT DEFAULT '[]',
    redirects TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    scanner_ip TEXT DEFAULT '',
    incident_id TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS response_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL UNIQUE,
    ts TEXT NOT NULL,
    incident_id TEXT DEFAULT '',
    policy TEXT DEFAULT '',
    action TEXT NOT NULL,
    reason TEXT DEFAULT '',
    actor TEXT NOT NULL,
    result TEXT DEFAULT 'PENDING',
    detail TEXT DEFAULT '{}',
    rollback TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS threat_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    source TEXT DEFAULT 'local',
    verdict TEXT DEFAULT 'malicious',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(ioc_type, ioc_value)
);

CREATE TABLE IF NOT EXISTS model_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    trained_at TEXT NOT NULL,
    trained_samples INTEGER DEFAULT 0,
    params TEXT DEFAULT '{}',
    metrics TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS server_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    ts TEXT NOT NULL,
    cpu REAL DEFAULT 0,
    memory REAL DEFAULT 0,
    disk REAL DEFAULT 0,
    network_mbps REAL DEFAULT 0,
    connections INTEGER DEFAULT 0,
    connections_delta INTEGER DEFAULT 0,
    process_count INTEGER DEFAULT 0,
    bytes_sent INTEGER DEFAULT 0,
    bytes_recv INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_server_stats_host_ts ON server_stats(hostname, ts DESC);

CREATE TABLE IF NOT EXISTS backup_protection (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    affected_files TEXT DEFAULT '[]',
    backup_targets TEXT DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_backup_protection_incident ON backup_protection(incident_id);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id TEXT NOT NULL UNIQUE,
    report_type TEXT NOT NULL CHECK(report_type IN ('daily','posture','incident')),
    title TEXT NOT NULL,
    period_start TEXT DEFAULT '',
    period_end TEXT DEFAULT '',
    summary TEXT DEFAULT '',
    content TEXT DEFAULT '{}',
    created_by TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    notification_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    body TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    channel TEXT DEFAULT 'in-app',
    alert_id TEXT DEFAULT '',
    incident_id TEXT DEFAULT '',
    read INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id TEXT NOT NULL UNIQUE,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    verdict TEXT DEFAULT 'unknown',
    confidence REAL DEFAULT 0.0,
    source TEXT DEFAULT 'manual',
    tags TEXT DEFAULT '[]',
    tlp TEXT DEFAULT 'WHITE',
    threat_actor TEXT DEFAULT '',
    kill_chain_phase TEXT DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    created_by TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT,
    UNIQUE(ioc_type, ioc_value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_verdict ON iocs(verdict);

CREATE TABLE IF NOT EXISTS ioc_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    matched_at TEXT NOT NULL,
    context TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_ioc_matches_ioc ON ioc_matches(ioc_id);
CREATE INDEX IF NOT EXISTS idx_ioc_matches_event ON ioc_matches(event_id);

CREATE TABLE IF NOT EXISTS alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    action TEXT NOT NULL,
    from_status TEXT DEFAULT '',
    to_status TEXT DEFAULT '',
    actor TEXT DEFAULT '',
    note TEXT DEFAULT '',
    ts TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alert_history_alert ON alert_history(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_history_ts ON alert_history(ts DESC);

CREATE TABLE IF NOT EXISTS incident_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    action TEXT NOT NULL,
    from_status TEXT DEFAULT '',
    to_status TEXT DEFAULT '',
    actor TEXT DEFAULT '',
    note TEXT DEFAULT '',
    ts TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incident_history_incident ON incident_history(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_history_ts ON incident_history(ts DESC);

CREATE TABLE IF NOT EXISTS investigation_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    note TEXT NOT NULL,
    author TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notes_entity ON investigation_notes(entity_type, entity_id);

CREATE TABLE IF NOT EXISTS saved_hunts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    query_text TEXT DEFAULT '',
    query_filters TEXT DEFAULT '{}',
    created_by TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT,
    last_run_at TEXT,
    run_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hunt_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL UNIQUE,
    hunt_id TEXT NOT NULL,
    result_count INTEGER DEFAULT 0,
    duration_ms REAL DEFAULT 0,
    ts TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hunt_runs_hunt ON hunt_runs(hunt_id);

CREATE TABLE IF NOT EXISTS user_risk (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    risk_score INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'low',
    risk_factors TEXT DEFAULT '[]',
    events_count INTEGER DEFAULT 0,
    alerts_count INTEGER DEFAULT 0,
    incidents_count INTEGER DEFAULT 0,
    last_event_at TEXT,
    calculated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_risk_score ON user_risk(risk_score DESC);

CREATE TABLE IF NOT EXISTS asset_risk (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL UNIQUE,
    risk_score INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'low',
    risk_factors TEXT DEFAULT '[]',
    events_count INTEGER DEFAULT 0,
    alerts_count INTEGER DEFAULT 0,
    incidents_count INTEGER DEFAULT 0,
    last_event_at TEXT,
    calculated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_asset_risk_score ON asset_risk(risk_score DESC);

CREATE TABLE IF NOT EXISTS metric_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_name TEXT NOT NULL,
    value REAL DEFAULT 0,
    labels TEXT DEFAULT '{}',
    ts TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_metric_history_name_ts ON metric_history(metric_name, ts DESC);

CREATE TABLE IF NOT EXISTS response_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_id TEXT NOT NULL UNIQUE,
    action_type TEXT NOT NULL,
    action_params TEXT DEFAULT '{}',
    incident_id TEXT DEFAULT '',
    requested_by TEXT NOT NULL,
    approved_by TEXT DEFAULT '',
    status TEXT DEFAULT 'PENDING',
    reason TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON response_approvals(status);

CREATE TABLE IF NOT EXISTS integration_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    integration_type TEXT NOT NULL,
    status TEXT DEFAULT 'NOT_CONFIGURED',
    config TEXT DEFAULT '{}',
    last_check_at TEXT,
    error_message TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT NOT NULL UNIQUE,
    key_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    scope TEXT DEFAULT 'read',
    role TEXT DEFAULT 'VIEWER',
    created_by TEXT DEFAULT '',
    description TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT,
    last_used_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'OPEN',
    severity TEXT DEFAULT 'medium',
    category TEXT DEFAULT '',
    assigned_to TEXT DEFAULT '',
    created_by TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT,
    resolved_at TEXT,
    resolution TEXT DEFAULT '',
    detection_gap INTEGER DEFAULT 0,
    gap_summary TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS case_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    added_at TEXT NOT NULL,
    UNIQUE(case_id, incident_id)
);

CREATE TABLE IF NOT EXISTS case_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    added_at TEXT NOT NULL,
    UNIQUE(case_id, alert_id)
);

CREATE TABLE IF NOT EXISTS case_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    note TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL UNIQUE,
    incident_id TEXT DEFAULT '',
    alert_id TEXT DEFAULT '',
    case_id TEXT DEFAULT '',
    event_ids TEXT DEFAULT '[]',
    type TEXT DEFAULT 'artifact',
    title TEXT DEFAULT '',
    description TEXT DEFAULT '',
    source TEXT DEFAULT '',
    content_raw TEXT DEFAULT '',
    content_hash TEXT DEFAULT '',
    integrity_status TEXT DEFAULT 'VERIFIED',
    created_by TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    metadata TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS soc_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL UNIQUE,
    incident_id TEXT DEFAULT '',
    case_id TEXT DEFAULT '',
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    owner TEXT DEFAULT '',
    priority TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'TODO',
    due_at TEXT,
    created_by TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS sla_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    severity TEXT NOT NULL UNIQUE,
    target_minutes INTEGER NOT NULL,
    enabled INTEGER DEFAULT 1,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS posture_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    score INTEGER NOT NULL,
    status TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


SLA_DEFAULT_POLICIES = {
    "critical": 30,
    "high": 120,
    "medium": 480,
    "low": 2880,
}


_SCHEMA_COLUMNS = {
    "events": [
        ("source_type", "TEXT DEFAULT 'telemetry'"),
        ("environment", "TEXT DEFAULT ''"),
        ("asset_id", "TEXT DEFAULT ''"),
        ("is_simulated", "INTEGER DEFAULT 0"),
        ("normalized_at", "TEXT"),
        ("processed_at", "TEXT"),
        ("detected_at", "TEXT"),
        ("correlated_at", "TEXT"),
        ("alert_created_at", "TEXT"),
        ("incident_created_at", "TEXT"),
        ("dashboard_delivered_at", "TEXT"),
        ("raw_evidence_hash", "TEXT DEFAULT ''"),
    ],
    "servers": [
        ("environment", "TEXT DEFAULT ''"),
        ("agent_id", "TEXT DEFAULT ''"),
        ("last_heartbeat_at", "TEXT"),
    ],
    "detection_rules": [
        ("version", "INTEGER DEFAULT 1"),
    ],
    "server_stats": [
        ("connections_delta", "INTEGER DEFAULT 0"),
    ],
    "phishing_scans": [
        ("incident_id", "TEXT DEFAULT ''"),
    ],
    "alerts": [
        ("acknowledged_at", "TEXT"),
        ("resolved_at", "TEXT"),
    ],
    "incidents": [
        ("acknowledged_at", "TEXT"),
        ("assigned_to", "TEXT DEFAULT ''"),
    ],
    "users": [
        ("mfa_secret", "TEXT DEFAULT ''"),
        ("mfa_enabled", "INTEGER DEFAULT 0"),
        ("mfa_confirmed_at", "TEXT"),
    ],
    "notifications": [
        ("alert_id", "TEXT DEFAULT ''"),
        ("incident_id", "TEXT DEFAULT ''"),
    ],
    "audit_logs": [
        ("prev_hash", "TEXT DEFAULT ''"),
        ("record_hash", "TEXT DEFAULT ''"),
    ],
}


def _ensure_columns() -> None:
    """Add columns introduced after the initial schema (idempotent migration)."""
    conn = get_connection()
    for table, cols in _SCHEMA_COLUMNS.items():
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in cols:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def init_schema() -> None:
    conn = _conn or get_connection()
    conn.executescript(SCHEMA)
    _ensure_columns()
    _chain_audit()
    _seed_sla_policies(conn)
    conn.commit()


def _seed_sla_policies(conn: sqlite3.Connection) -> None:
    """Seed incident SLA targets per severity when none exist yet."""
    if conn.execute("SELECT COUNT(*) FROM sla_policies").fetchone()[0] > 0:
        return
    now = _now()
    for severity, target in SLA_DEFAULT_POLICIES.items():
        conn.execute(
            "INSERT OR IGNORE INTO sla_policies(severity, target_minutes, enabled, updated_at) VALUES(?,?,1,?)",
            (severity, target, now),
        )


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #
def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    for key in ("details", "raw", "mitre", "timeline", "event_ids", "evidence",
                "detection_rules", "recommended_actions", "actions_taken",
                "reasons", "redirects", "params", "metrics", "detail", "tags", "config", "snapshot",
                "backup_targets", "affected_files", "content",
                "query_filters", "risk_factors", "action_params",
                "context", "labels"):
        if key in d:
            d[key] = _loads(d[key], [] if key not in ("details", "raw", "params", "metrics", "detail", "config", "tags", "snapshot", "context", "labels") else {})
    return d


def _execute(sql: str, params: tuple = ()) -> None:
    with db() as conn:
        conn.execute(sql, params)


def _fetch_one(sql: str, params: tuple = ()) -> Optional[dict]:
    with db() as conn:
        row = conn.execute(sql, params).fetchone()
        return _row_to_dict(row) if row else None


def _fetch_all(sql: str, params: tuple = ()) -> list[dict]:
    with db() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_dict(r) for r in rows]


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #
def create_user(username: str, password_hash: str, role: str, full_name: str = "") -> dict:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO users(username, password_hash, role, full_name, is_active, created_at) VALUES(?,?,?,?,1,?)",
            (username, password_hash, role, full_name, _now()),
        )
        uid = cur.lastrowid
    return get_user_by_id(uid)


def get_user_by_username(username: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM users WHERE username = ?", (username,))


def get_user_by_id(uid: int) -> Optional[dict]:
    return _fetch_one("SELECT * FROM users WHERE id = ?", (uid,))


def list_users() -> list[dict]:
    return _fetch_all("SELECT id, username, role, full_name, is_active, mfa_enabled, created_at, last_login_at "
                      "FROM users ORDER BY username")


def update_user(user_id: int, **fields) -> None:
    allowed = {"role", "full_name", "is_active", "password_hash", "last_login_at",
               "mfa_secret", "mfa_enabled", "mfa_confirmed_at"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(v)
    if not sets:
        return
    params.append(user_id)
    _execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", tuple(params))


def count_users() -> int:
    with db() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


# --------------------------------------------------------------------------- #
# API keys
# --------------------------------------------------------------------------- #
_API_KEY_PUBLIC = "id, key_id, name, scope, role, created_by, description, created_at, expires_at, last_used_at, revoked_at"


def create_api_key(key_id: str, key_hash: str, name: str, scope: str, role: str,
                   created_by: str, description: str, expires_at: Optional[str] = None) -> dict:
    with db() as conn:
        conn.execute(
            "INSERT INTO api_keys(key_id, key_hash, name, scope, role, created_by, description, created_at, expires_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (key_id, key_hash, name, scope, role, created_by, description, _now(), expires_at),
        )
    return get_api_key_public(key_id)


def get_api_key_public(key_id: str) -> Optional[dict]:
    return _fetch_one(f"SELECT {_API_KEY_PUBLIC} FROM api_keys WHERE key_id = ?", (key_id,))


def get_api_key_auth(key_id: str) -> Optional[dict]:
    return _fetch_one("SELECT key_id, key_hash, scope, role, expires_at, revoked_at FROM api_keys WHERE key_id = ?",
                      (key_id,))


def list_api_keys(include_revoked: bool = False) -> list[dict]:
    sql = f"SELECT {_API_KEY_PUBLIC} FROM api_keys"
    if not include_revoked:
        sql += " WHERE revoked_at IS NULL"
    return _fetch_all(sql + " ORDER BY created_at DESC")


def touch_api_key_last_used(key_id: str) -> None:
    _execute("UPDATE api_keys SET last_used_at = ? WHERE key_id = ?", (_now(), key_id))


def set_api_key_hash(key_id: str, key_hash: str) -> None:
    _execute("UPDATE api_keys SET key_hash = ?, last_used_at = NULL, revoked_at = NULL WHERE key_id = ?",
             (key_hash, key_id))


def update_api_key_meta(key_id: str, name: Optional[str] = None, scope: Optional[str] = None,
                        role: Optional[str] = None, description: Optional[str] = None) -> None:
    sets, params = [], []
    for k, v in [("name", name), ("scope", scope), ("role", role), ("description", description)]:
        if v is not None:
            sets.append(f"{k} = ?")
            params.append(v)
    if not sets:
        return
    params.append(key_id)
    _execute(f"UPDATE api_keys SET {', '.join(sets)} WHERE key_id = ?", tuple(params))


def revoke_api_key(key_id: str) -> None:
    _execute("UPDATE api_keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL", (_now(), key_id))


# --------------------------------------------------------------------------- #
# Cases (investigation containers)
# --------------------------------------------------------------------------- #
def create_case(title: str, description: str, severity: str, category: str,
                assigned_to: str, created_by: str) -> dict:
    case_id = new_id("cse")
    now = _now()
    with db() as conn:
        conn.execute(
            "INSERT INTO cases(case_id, title, description, status, severity, category, assigned_to, created_by, created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (case_id, title, description, "OPEN", severity, category, assigned_to, created_by, now),
        )
    return get_case(case_id)


def get_case(case_id: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM cases WHERE case_id = ?", (case_id,))


def list_cases(status: Optional[str] = None, assigned_to: Optional[str] = None) -> list[dict]:
    sql = "SELECT * FROM cases"
    clauses, params = [], []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if assigned_to:
        clauses.append("assigned_to = ?")
        params.append(assigned_to)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    return _fetch_all(sql + " ORDER BY created_at DESC", tuple(params))


def update_case(case_id: str, **fields) -> None:
    allowed = {"title", "description", "status", "severity", "category",
               "assigned_to", "resolved_at", "resolution", "detection_gap", "gap_summary"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(v)
    sets.append("updated_at = ?")
    params.append(_now())
    params.append(case_id)
    _execute(f"UPDATE cases SET {', '.join(sets)} WHERE case_id = ?", tuple(params))


def delete_case(case_id: str) -> None:
    _execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
    _execute("DELETE FROM case_incidents WHERE case_id = ?", (case_id,))
    _execute("DELETE FROM case_alerts WHERE case_id = ?", (case_id,))
    _execute("DELETE FROM case_notes WHERE case_id = ?", (case_id,))


def case_link_incident(case_id: str, incident_id: str) -> bool:
    with db() as conn:
        try:
            conn.execute("INSERT INTO case_incidents(case_id, incident_id, added_at) VALUES(?,?,?)",
                         (case_id, incident_id, _now()))
            return True
        except sqlite3.IntegrityError:
            return False


def case_unlink_incident(case_id: str, incident_id: str) -> None:
    _execute("DELETE FROM case_incidents WHERE case_id = ? AND incident_id = ?", (case_id, incident_id))


def case_link_alert(case_id: str, alert_id: str) -> bool:
    with db() as conn:
        try:
            conn.execute("INSERT INTO case_alerts(case_id, alert_id, added_at) VALUES(?,?,?)",
                         (case_id, alert_id, _now()))
            return True
        except sqlite3.IntegrityError:
            return False


def case_unlink_alert(case_id: str, alert_id: str) -> None:
    _execute("DELETE FROM case_alerts WHERE case_id = ? AND alert_id = ?", (case_id, alert_id))


def case_incident_ids(case_id: str) -> list[str]:
    return [r["incident_id"] for r in _fetch_all(
        "SELECT incident_id FROM case_incidents WHERE case_id = ? ORDER BY added_at", (case_id,))]


def case_alert_ids(case_id: str) -> list[str]:
    return [r["alert_id"] for r in _fetch_all(
        "SELECT alert_id FROM case_alerts WHERE case_id = ? ORDER BY added_at", (case_id,))]


def case_add_note(case_id: str, note: str, author: str) -> dict:
    with db() as conn:
        cur = conn.execute("INSERT INTO case_notes(case_id, note, author, created_at) VALUES(?,?,?,?)",
                           (case_id, note, author, _now()))
        nid = cur.lastrowid
    return _fetch_one("SELECT * FROM case_notes WHERE id = ?", (nid,))


def case_notes(case_id: str) -> list[dict]:
    return _fetch_all("SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at DESC", (case_id,))


# --------------------------------------------------------------------------- #
# Evidence (immutable, hash-verified)
# --------------------------------------------------------------------------- #
def create_evidence(evidence_id: str, incident_id: str, alert_id: str, case_id: str,
                    event_ids: list, etype: str, title: str, description: str,
                    source: str, content_raw: str, content_hash: str,
                    integrity_status: str, created_by: str, metadata: dict) -> dict:
    with db() as conn:
        conn.execute(
            "INSERT INTO evidence(evidence_id, incident_id, alert_id, case_id, event_ids, type, title, "
            "description, source, content_raw, content_hash, integrity_status, created_by, created_at, metadata) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (evidence_id, incident_id, alert_id, case_id, _json(event_ids), etype, title,
             description, source, content_raw, content_hash, integrity_status, created_by, _now(),
             _json(metadata or {})),
        )
    return get_evidence(evidence_id)


def get_evidence(evidence_id: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))


def get_evidence_by_id(rid: int) -> Optional[dict]:
    return _fetch_one("SELECT * FROM evidence WHERE id = ?", (rid,))


def list_evidence(incident_id: Optional[str] = None, case_id: Optional[str] = None,
                  alert_id: Optional[str] = None, limit: int = 100) -> list[dict]:
    sql = "SELECT * FROM evidence"
    clauses, params = [], []
    for col, val in (("incident_id", incident_id), ("case_id", case_id), ("alert_id", alert_id)):
        if val not in (None, ""):
            clauses.append(f"{col} = ?")
            params.append(val)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    return _fetch_all(sql + f" ORDER BY created_at DESC LIMIT {int(limit)}", tuple(params))


def update_evidence_integrity(evidence_id: str, status: str) -> None:
    _execute("UPDATE evidence SET integrity_status = ? WHERE evidence_id = ?", (status, evidence_id))


def delete_evidence(evidence_id: str) -> None:
    _execute("DELETE FROM evidence WHERE evidence_id = ?", (evidence_id,))


# --------------------------------------------------------------------------- #
# SOC tasks
# --------------------------------------------------------------------------- #
def create_task(task_id: str, incident_id: str, case_id: str, title: str, description: str,
                owner: str, priority: str, due_at: Optional[str], created_by: str) -> dict:
    with db() as conn:
        conn.execute(
            "INSERT INTO soc_tasks(task_id, incident_id, case_id, title, description, owner, priority, "
            "status, due_at, created_by, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (task_id, incident_id, case_id, title, description, owner, priority, "TODO", due_at,
             created_by, _now()),
        )
    return get_task(task_id)


def get_task(task_id: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM soc_tasks WHERE task_id = ?", (task_id,))


def list_tasks(incident_id: Optional[str] = None, case_id: Optional[str] = None,
               status: Optional[str] = None, owner: Optional[str] = None, limit: int = 200) -> list[dict]:
    sql = "SELECT * FROM soc_tasks"
    clauses, params = [], []
    for col, val in (("incident_id", incident_id), ("case_id", case_id), ("status", status), ("owner", owner)):
        if val not in (None, ""):
            clauses.append(f"{col} = ?")
            params.append(val)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    return _fetch_all(sql + f" ORDER BY created_at DESC LIMIT {int(limit)}", tuple(params))


def update_task(task_id: str, **fields) -> None:
    allowed = {"incident_id", "case_id", "title", "description", "owner", "priority",
               "status", "due_at", "completed_at"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(v)
    if not sets:
        return
    params.append(task_id)
    _execute(f"UPDATE soc_tasks SET {', '.join(sets)} WHERE task_id = ?", tuple(params))


def delete_task(task_id: str) -> None:
    _execute("DELETE FROM soc_tasks WHERE task_id = ?", (task_id,))


# --------------------------------------------------------------------------- #
# SLA policies
# --------------------------------------------------------------------------- #
def list_sla_policies() -> list[dict]:
    return _fetch_all("SELECT severity, target_minutes, enabled, updated_at FROM sla_policies "
                      "ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END")


def get_sla_policy(severity: str) -> Optional[dict]:
    return _fetch_one("SELECT severity, target_minutes, enabled FROM sla_policies WHERE severity = ?", (severity,))


def upsert_sla_policy(severity: str, target_minutes: int, enabled: bool) -> dict:
    with db() as conn:
        conn.execute(
            """INSERT INTO sla_policies(severity, target_minutes, enabled, updated_at)
               VALUES(?,?,?,?) ON CONFLICT(severity) DO UPDATE
               SET target_minutes = excluded.target_minutes, enabled = excluded.enabled, updated_at = excluded.updated_at""",
            (severity, target_minutes, int(enabled), _now()),
        )
    return get_sla_policy(severity)


# --------------------------------------------------------------------------- #
# Posture history
# --------------------------------------------------------------------------- #
def save_posture_snapshot(score: int, status: str, snapshot: dict) -> dict:
    created = _now()
    with db() as conn:
        conn.execute(
            "INSERT INTO posture_history(score, status, snapshot, created_at) VALUES(?,?,?,?)",
            (score, status, _json(snapshot), created),
        )
    return {"score": score, "status": status, "created_at": created}


def list_posture_history(limit: int = 30) -> list[dict]:
    return _fetch_all(
        "SELECT id, score, status, snapshot, created_at FROM posture_history ORDER BY created_at DESC LIMIT ?",
        (limit,),
    )


# --------------------------------------------------------------------------- #
# Servers
# --------------------------------------------------------------------------- #
def upsert_server(hostname: str, data: dict) -> dict:
    ip = data.get("ip", "")
    os_name = data.get("os", "")
    platform = data.get("platform", "")
    status = data.get("status", "online")
    cpu = data.get("cpu", 0)
    memory = data.get("memory", 0)
    disk = data.get("disk", 0)
    processes = data.get("processes", 0)
    uptime = data.get("uptime", 0)
    environment = data.get("environment", "")
    agent_id = data.get("agent_id", "")
    tags = json.dumps(data.get("tags", []), default=str)
    with db() as conn:
        conn.execute(
            """INSERT INTO servers(hostname, ip, os, platform, status, cpu, memory, disk, processes, uptime, last_seen_at,
               environment, agent_id, last_heartbeat_at, tags, created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(hostname) DO UPDATE SET
                 ip=excluded.ip, os=excluded.os, platform=excluded.platform, status=excluded.status,
                 cpu=excluded.cpu, memory=excluded.memory, disk=excluded.disk, processes=excluded.processes,
                 uptime=excluded.uptime, last_seen_at=excluded.last_seen_at, environment=excluded.environment,
                 agent_id=excluded.agent_id, last_heartbeat_at=excluded.last_heartbeat_at, tags=excluded.tags""",
            (hostname, ip, os_name, platform, status, cpu, memory, disk, processes, uptime, _now(),
             environment, agent_id, _now(), tags, _now()),
        )
    return get_server(hostname)


def get_server(hostname: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM servers WHERE hostname = ?", (hostname,))


def list_servers() -> list[dict]:
    return _fetch_all("SELECT * FROM servers ORDER BY hostname")


def list_server_stats(hostname: str, limit: int = 120) -> list[dict]:
    return _fetch_all(
        "SELECT ts, cpu, memory, disk, network_mbps, connections, connections_delta, process_count FROM server_stats WHERE hostname=? ORDER BY ts DESC LIMIT ?",
        (hostname, limit),
    )


def save_server_stats(hostname: str, stats: dict) -> None:
    _execute(
        """INSERT INTO server_stats(hostname, ts, cpu, memory, disk, network_mbps, connections, connections_delta, process_count, bytes_sent, bytes_recv)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (hostname, _now(), stats.get("cpu", 0), stats.get("memory", 0), stats.get("disk", 0),
         stats.get("network_mbps", 0), stats.get("connections", 0), stats.get("connections_delta", 0),
         stats.get("process_count", 0), stats.get("bytes_sent", 0), stats.get("bytes_recv", 0)),
    )


# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #
def save_event(event: dict) -> dict:
    ev = dict(event)
    if not ev.get("event_id"):
        ev["event_id"] = new_id("evt")
    if not ev.get("ts"):
        ev["ts"] = _now()
    if not ev.get("ingested_at"):
        ev["ingested_at"] = _now()
    try:
        with db() as conn:
            conn.execute(
                """INSERT INTO events(event_id, ts, source, source_type, host, environment, asset_id, is_simulated,
                   event_type, category, severity, confidence, risk_score, source_ip, dest_ip, port, protocol,
                   username, target, process, command, details, mitre, raw, ingested_at, normalized_at, processed_at,
                   detected_at, correlated_at, alert_created_at, incident_created_at, dashboard_delivered_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ev["event_id"], ev["ts"], ev.get("source", "system"), ev.get("source_type", "telemetry"),
                 ev.get("host", ""), ev.get("environment", ""), ev.get("asset_id", ""), int(ev.get("is_simulated", 0)),
                 ev.get("event_type", "unknown"), ev.get("category", ""), ev.get("severity", "info"),
                 ev.get("confidence", 0.0), ev.get("risk_score", 0), ev.get("source_ip", ""), ev.get("dest_ip", ""),
                 ev.get("port", 0), ev.get("protocol", ""), ev.get("username", ""), ev.get("target", ""),
                 ev.get("process", ""), ev.get("command", ""), _json(ev.get("details", {})), _json(ev.get("mitre", [])),
                 _json(ev.get("raw", {})), ev["ingested_at"], ev.get("normalized_at"), ev.get("processed_at"),
                 ev.get("detected_at"), ev.get("correlated_at"), ev.get("alert_created_at"),
                 ev.get("incident_created_at"), ev.get("dashboard_delivered_at")),
            )
        ev["_deduplicated"] = False
        return ev
    except sqlite3.IntegrityError:
        # Duplicate event_id (replay / out-of-order delivery). Treat as a
        # duplicate, never drop silently: the stored event is returned.
        stored = get_event_by_id(ev["event_id"]) or ev
        stored["_deduplicated"] = True
        return stored


def get_event_by_id(event_id: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM events WHERE event_id = ?", (event_id,))


def list_events(limit: int = 100, event_type: Optional[str] = None, host: Optional[str] = None,
                severity: Optional[str] = None, source_ip: Optional[str] = None,
                environment: Optional[str] = None) -> list[dict]:
    clauses, params = ["1=1"], []
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if host:
        clauses.append("host = ?")
        params.append(host)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if source_ip:
        clauses.append("source_ip = ?")
        params.append(source_ip)
    if environment:
        clauses.append("environment = ?")
        params.append(environment)
    sql = f"SELECT * FROM events WHERE {' AND '.join(clauses)} ORDER BY ts DESC LIMIT ?"
    params.append(limit)
    return _fetch_all(sql, tuple(params))


def count_events(since: Optional[str] = None) -> int:
    if since:
        return _fetch_one("SELECT COUNT(*) AS c FROM events WHERE ingested_at >= ?", (since,))["c"]
    return _fetch_one("SELECT COUNT(*) AS c FROM events")["c"]


def _events_meta_between(start: str, end: str) -> list[dict]:
    return _fetch_all(
        "SELECT event_type, category, severity, source_ip, dest_ip, host, username, target, port, protocol FROM events WHERE ts >= ? AND ts <= ?",
        (start, end),
    )


def query_events(since_ts: Optional[str] = None, minutes: Optional[int] = None, limit: int = 500) -> list[dict]:
    """Fetch recent events, optionally for windowed analysis (minutes)."""
    if minutes:
        from datetime import datetime, timedelta, timezone
        start = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        return _fetch_all("SELECT * FROM events WHERE ts >= ? ORDER BY ts DESC LIMIT ?", (start, limit))
    if since_ts:
        return _fetch_all("SELECT * FROM events WHERE ts >= ? ORDER BY ts DESC LIMIT ?", (since_ts, limit))
    return list_events(limit=limit)


def net_connection_columns(since: Optional[str] = None) -> list[dict]:
    """Source/dest/port columns of net.connection events (for traffic aggregates)."""
    if since:
        return _fetch_all(
            "SELECT source_ip, dest_ip, port FROM events WHERE event_type='net.connection' AND ts >= ?",
            (since,),
        )
    return _fetch_all(
        "SELECT source_ip, dest_ip, port FROM events WHERE event_type='net.connection'",
    )


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #
def save_alert(alert: dict) -> dict:
    al = dict(alert)
    al["alert_id"] = al.get("alert_id") or new_id("alr")
    al["created_at"] = al.get("created_at") or _now()
    with db() as conn:
        conn.execute(
            """INSERT INTO alerts(alert_id, title, description, severity, risk_score, status, source, event_ids, created_at, group_key)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (al["alert_id"], al.get("title", "Alert"), al.get("description", ""), al.get("severity", "medium"),
             al.get("risk_score", 0), al.get("status", "NEW"), al.get("source", ""), _json(al.get("event_ids", [])),
             al["created_at"], al.get("group_key", "")),
        )
    return get_alert(al["alert_id"])


def find_open_alert_by_group(group_key: str, window_minutes: int = 30) -> Optional[dict]:
    since = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    return _fetch_one(
        "SELECT * FROM alerts WHERE group_key = ? AND status NOT IN ('RESOLVED','FALSE_POSITIVE') AND created_at >= ? ORDER BY created_at DESC LIMIT 1",
        (group_key, since),
    )


def get_alert(alert_id: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))


def list_alerts(limit: int = 100, severity: Optional[str] = None, status: Optional[str] = None) -> list[dict]:
    clauses, params = ["1=1"], []
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if status:
        clauses.append("status = ?")
        params.append(status)
    params.append(limit)
    return _fetch_all(f"SELECT * FROM alerts WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT ?", tuple(params))


def update_alert(alert_id: str, **fields) -> None:
    allowed = {"status", "assigned_to", "feedback", "description"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(v)
    if "status" in fields:
        new_status = fields["status"]
        if new_status != "NEW":
            sets.append("acknowledged_at = COALESCE(acknowledged_at, ?)")
            params.append(_now())
        if new_status in ("RESOLVED", "FALSE_POSITIVE"):
            sets.append("resolved_at = ?")
            params.append(_now())
    if not sets:
        return
    sets.append("updated_at = ?")
    params.append(_now())
    params.append(alert_id)
    _execute(f"UPDATE alerts SET {', '.join(sets)} WHERE alert_id = ?", tuple(params))


def update_alert_event_ids(alert_id: str, event_ids: list) -> None:
    _execute("UPDATE alerts SET event_ids = ?, updated_at = ? WHERE alert_id = ?",
             (_json(event_ids), _now(), alert_id))


def count_alerts(since: Optional[str] = None, severity: Optional[str] = None) -> int:
    clauses, params = ["1=1"], []
    if since:
        clauses.append("created_at >= ?")
        params.append(since)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    return _fetch_one(f"SELECT COUNT(*) AS c FROM alerts WHERE {' AND '.join(clauses)}", tuple(params))["c"]


# --------------------------------------------------------------------------- #
# Incidents
# --------------------------------------------------------------------------- #
def save_incident(inc: dict) -> dict:
    i = dict(inc)
    i["incident_id"] = i.get("incident_id") or new_id("inc")
    i["created_at"] = i.get("created_at") or _now()
    with db() as conn:
        conn.execute(
            """INSERT INTO incidents(incident_id, title, severity, status, risk_score, confidence, category,
               affected_host, affected_user, source_ip, dest_ip, timeline, event_ids, evidence, mitre,
               ai_explanation, detection_rules, recommended_actions, actions_taken, analyst_notes, created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (i["incident_id"], i.get("title", "Incident"), i.get("severity", "medium"), i.get("status", "NEW"),
             i.get("risk_score", 0), i.get("confidence", 0.0), i.get("category", ""),
             i.get("affected_host", ""), i.get("affected_user", ""), i.get("source_ip", ""), i.get("dest_ip", ""),
             _json(i.get("timeline", [])), _json(i.get("event_ids", [])), _json(i.get("evidence", [])),
             _json(i.get("mitre", [])), i.get("ai_explanation", ""), _json(i.get("detection_rules", [])),
             _json(i.get("recommended_actions", [])), _json(i.get("actions_taken", [])), i.get("analyst_notes", ""), i["created_at"]),
        )
    for eid in i.get("event_ids", []):
        with db() as conn:
            conn.execute("INSERT OR IGNORE INTO incident_events(incident_id, event_id) VALUES(?,?)", (i["incident_id"], eid))
    return get_incident(i["incident_id"])


def get_incident(incident_id: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))


def list_incidents(limit: int = 100, status: Optional[str] = None, severity: Optional[str] = None) -> list[dict]:
    clauses, params = ["1=1"], []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    params.append(limit)
    return _fetch_all(f"SELECT * FROM incidents WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT ?", tuple(params))


def update_incident(incident_id: str, **fields) -> None:
    allowed = {"status", "severity", "analyst_notes", "recovery_status", "assigned_to",
               "recommended_actions", "actions_taken", "evidence", "ai_explanation"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(_json(v) if isinstance(v, (list, dict)) else v)
    if "status" in fields:
        if fields["status"] in ("RESOLVED", "FALSE_POSITIVE"):
            sets.append("resolved_at = ?")
            params.append(_now())
        elif fields["status"] != "NEW":
            sets.append("acknowledged_at = COALESCE(acknowledged_at, ?)")
            params.append(_now())
    if not sets:
        return
    sets.append("updated_at = ?")
    params.append(_now())
    params.append(incident_id)
    _execute(f"UPDATE incidents SET {', '.join(sets)} WHERE incident_id = ?", tuple(params))


def link_event_to_incident(incident_id: str, event_id: str) -> None:
    _execute("INSERT OR IGNORE INTO incident_events(incident_id, event_id) VALUES(?,?)", (incident_id, event_id))


def count_incidents(status: Optional[str] = None) -> int:
    if status:
        return _fetch_one("SELECT COUNT(*) AS c FROM incidents WHERE status = ?", (status,))["c"]
    return _fetch_one("SELECT COUNT(*) AS c FROM incidents")["c"]


# --------------------------------------------------------------------------- #
# Detection rules
# --------------------------------------------------------------------------- #
def upsert_rule(rule: dict) -> dict:
    r = dict(rule)
    r["rule_id"] = r.get("rule_id") or new_id("rule")
    r["created_at"] = r.get("created_at") or _now()
    with db() as conn:
        conn.execute(
            """INSERT INTO detection_rules(rule_id, name, description, category, enabled, severity, mitre, config, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(rule_id) DO UPDATE SET name=excluded.name, description=excluded.description,
                 category=excluded.category, enabled=excluded.enabled, severity=excluded.severity,
                 mitre=excluded.mitre, config=excluded.config, updated_at=excluded.updated_at""",
            (r["rule_id"], r.get("name", r["rule_id"]), r.get("description", ""), r.get("category", ""),
             int(r.get("enabled", 1)), r.get("severity", "medium"), _json(r.get("mitre", [])),
             _json(r.get("config", {})), r["created_at"], _now()),
        )
    return get_rule(r["rule_id"])


def get_rule(rule_id: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM detection_rules WHERE rule_id = ?", (rule_id,))


def create_rule(rule: dict, changed_by: str = "") -> dict:
    """Insert a brand-new rule with version 1 and an immutable history entry."""
    r = dict(rule)
    r["rule_id"] = r.get("rule_id") or new_id("rule")
    r["created_at"] = _now()
    with db() as conn:
        conn.execute(
            """INSERT INTO detection_rules(rule_id, name, description, category, enabled, severity, mitre, config, version, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (r["rule_id"], r.get("name", r["rule_id"]), r.get("description", ""), r.get("category", ""),
             int(r.get("enabled", 1)), r.get("severity", "medium"), _json(r.get("mitre", [])),
             _json(r.get("config", {})), 1, r["created_at"], _now()),
        )
    snapshot = get_rule(r["rule_id"])
    save_rule_history(r["rule_id"], 1, snapshot, action="create", changed_by=changed_by)
    return snapshot


def update_rule_with_history(rule_id: str, fields: dict, changed_by: str = "") -> dict:
    """Apply changes to an existing rule, snapshotting the previous state and
    incrementing the version (immutable audit trail)."""
    current = get_rule(rule_id)
    if not current:
        raise KeyError(rule_id)
    version = int(current.get("version", 1))
    save_rule_history(rule_id, version, current, action="update", changed_by=changed_by)
    allowed = {"name", "description", "category", "enabled", "severity", "mitre", "config"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(_json(v) if isinstance(v, (list, dict)) else v)
    params.append(version + 1)
    params.append(_now())
    params.append(rule_id)
    _execute(f"UPDATE detection_rules SET {', '.join(sets)}, version = ?, updated_at = ? WHERE rule_id = ?",
             tuple(params))
    return get_rule(rule_id)


def restore_rule_snapshot(rule_id: str, snapshot: dict, changed_by: str = "") -> dict:
    """Roll back a rule to a previous snapshot (new version, history preserved)."""
    current = get_rule(rule_id)
    version = int(current.get("version", 1)) + 1
    save_rule_history(rule_id, version, snapshot, action="rollback", changed_by=changed_by)
    _execute(
        """UPDATE detection_rules SET name=?, description=?, category=?, enabled=?, severity=?, mitre=?, config=?,
           version=?, updated_at=? WHERE rule_id=?""",
        (snapshot.get("name", rule_id), snapshot.get("description", ""), snapshot.get("category", ""),
         int(snapshot.get("enabled", 1)), snapshot.get("severity", "medium"), _json(snapshot.get("mitre", [])),
         _json(snapshot.get("config", {})), version, _now(), rule_id),
    )
    return get_rule(rule_id)


def list_rules(enabled_only: bool = False) -> list[dict]:
    if enabled_only:
        return _fetch_all("SELECT * FROM detection_rules WHERE enabled = 1 ORDER BY category, name")
    return _fetch_all("SELECT * FROM detection_rules ORDER BY category, name")


def set_rule_enabled(rule_id: str, enabled: bool) -> None:
    _execute("UPDATE detection_rules SET enabled = ?, updated_at = ? WHERE rule_id = ?", (int(enabled), _now(), rule_id))


def update_event_latencies(event_id: str, **fields) -> None:
    """Stamp pipeline lifecycle timestamps on a stored event (idempotent)."""
    allowed = {"processed_at", "detected_at", "correlated_at", "alert_created_at",
               "incident_created_at", "dashboard_delivered_at"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed and v:
            sets.append(f"{k} = COALESCE({k}, ?)")
            params.append(v)
    if not sets:
        return
    params.append(event_id)
    _execute(f"UPDATE events SET {', '.join(sets)} WHERE event_id = ?", tuple(params))


# --------------------------------------------------------------------------- #
# Agents (endpoint telemetry sources)
# --------------------------------------------------------------------------- #
def upsert_agent_heartbeat(agent_id: str, data: dict) -> dict:
    now = _now()
    with db() as conn:
        conn.execute(
            """INSERT INTO agents(agent_id, hostname, ip, os, environment, version, status, last_heartbeat_at, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(agent_id) DO UPDATE SET
                 hostname=excluded.hostname, ip=excluded.ip, os=excluded.os,
                 environment=excluded.environment, version=excluded.version,
                 status=excluded.status, last_heartbeat_at=excluded.last_heartbeat_at""",
            (agent_id, data.get("hostname", ""), data.get("ip", ""), data.get("os", ""),
             data.get("environment", ""), data.get("version", ""), data.get("status", "HEALTHY"), now, now),
        )
    return get_agent(agent_id)


def get_agent(agent_id: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))


def list_agents() -> list[dict]:
    return _fetch_all("SELECT * FROM agents ORDER BY last_heartbeat_at DESC")


# --------------------------------------------------------------------------- #
# Rule history / versioning
# --------------------------------------------------------------------------- #
def save_rule_history(rule_id: str, version: int, snapshot: dict, action: str, changed_by: str = "") -> None:
    _execute(
        "INSERT INTO rule_history(rule_id, version, action, snapshot, changed_by, changed_at) VALUES(?,?,?,?,?,?)",
        (rule_id, version, action, _json(snapshot), changed_by, _now()),
    )


def list_rule_history(rule_id: str, limit: int = 50) -> list[dict]:
    return _fetch_all(
        "SELECT * FROM rule_history WHERE rule_id = ? ORDER BY version DESC LIMIT ?", (rule_id, limit),
    )


def get_rule_snapshot(rule_id: str, version: int) -> Optional[dict]:
    return _fetch_one(
        "SELECT * FROM rule_history WHERE rule_id = ? AND version = ?", (rule_id, version),
    )


def delete_rule(rule_id: str) -> None:
    _execute("DELETE FROM detection_rules WHERE rule_id = ?", (rule_id,))
    # History is kept (immutable audit trail).


# --------------------------------------------------------------------------- #
# Audit logs
# --------------------------------------------------------------------------- #
def _audit_payload(ts: str, actor: str, role: str, action: str, target: str,
                   result: str, ip: str, detail_json: str) -> bytes:
    """Canonical message signed into each audit record (tamper-evident chain)."""
    return "|".join([ts, actor, role, action, target, result, ip, detail_json]).encode("utf-8")


def _audit_record_hash(prev_hash: str, ts: str, actor: str, role: str, action: str,
                       target: str, result: str, ip: str, detail_json: str) -> str:
    payload = prev_hash.encode("utf-8") + b"::" + _audit_payload(
        ts, actor, role, action, target, result, ip, detail_json
    )
    return hmac.new(settings.AUTH_SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _last_audit_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT record_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
    return (row[0] or "") if row else ""


def log_audit(actor: str, action: str, result: str = "SUCCESS", target: str = "",
              detail: dict | None = None, role: str = "", ip: str = "") -> None:
    ts = _now()
    detail_json = _json(detail or {})
    with db() as conn:
        prev = _last_audit_hash(conn)
        record_hash = _audit_record_hash(prev, ts, actor, role, action, target, result, ip, detail_json)
        conn.execute(
            "INSERT INTO audit_logs(ts, actor, actor_role, action, target, result, ip, detail, prev_hash, record_hash) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ts, actor, role, action, target, result, ip, detail_json, prev, record_hash),
        )


def _chain_audit() -> None:
    """Backfill record hashes for rows written before the hash chain existed."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, ts, actor, actor_role, action, target, result, ip, detail, record_hash "
        "FROM audit_logs ORDER BY id ASC"
    ).fetchall()
    prev = ""
    for r in rows:
        if r["record_hash"]:
            prev = r["record_hash"]
            continue
        expected = _audit_record_hash(
            prev, r["ts"], r["actor"], r["actor_role"], r["action"],
            r["target"], r["result"], r["ip"], r["detail"],
        )
        conn.execute(
            "UPDATE audit_logs SET prev_hash = ?, record_hash = ? WHERE id = ?",
            (prev, expected, r["id"]),
        )
        prev = expected


def _rechain_audit() -> None:
    """Rewrite the entire hash chain in place (used to repair after a legitimate
    administrative correction; the audit trail remains verifiable)."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, ts, actor, actor_role, action, target, result, ip, detail "
        "FROM audit_logs ORDER BY id ASC"
    ).fetchall()
    prev = ""
    for r in rows:
        expected = _audit_record_hash(prev, r["ts"], r["actor"], r["actor_role"], r["action"],
                                      r["target"], r["result"], r["ip"], r["detail"])
        conn.execute(
            "UPDATE audit_logs SET prev_hash = ?, record_hash = ? WHERE id = ?",
            (prev, expected, r["id"]),
        )
        prev = expected


def verify_audit_chain() -> dict:
    """Recompute the hash chain and report any tampered or broken records."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, ts, actor, actor_role, action, target, result, ip, detail, prev_hash, record_hash "
        "FROM audit_logs ORDER BY id ASC"
    ).fetchall()
    tampered: list[int] = []
    broken_links: list[int] = []
    prev = ""
    for r in rows:
        expected = _audit_record_hash(
            prev, r["ts"], r["actor"], r["actor_role"], r["action"],
            r["target"], r["result"], r["ip"], r["detail"],
        )
        if r["record_hash"] != expected:
            tampered.append(r["id"])
        if (r["prev_hash"] or "") != prev:
            broken_links.append(r["id"])
        prev = r["record_hash"] or ""
    return {
        "records": len(rows),
        "verified": len(rows) - len(tampered),
        "tampered": tampered,
        "broken_links": broken_links,
        "integrity": "OK" if not tampered and not broken_links else "COMPROMISED",
    }


def list_audit(limit: int = 200, actor: Optional[str] = None) -> list[dict]:
    if actor:
        return _fetch_all("SELECT * FROM audit_logs WHERE actor = ? ORDER BY ts DESC LIMIT ?", (actor, limit))
    return _fetch_all("SELECT * FROM audit_logs ORDER BY ts DESC LIMIT ?", (limit,))


def count_audit_errors(action: str = "pipeline.process_error", since: Optional[str] = None) -> int:
    clauses = ["action = ? AND result = 'FAILED'"]
    params = [action]
    if since:
        clauses.append("ts >= ?")
        params.append(since)
    row = _fetch_one(f"SELECT COUNT(*) AS c FROM audit_logs WHERE {' AND '.join(clauses)}", tuple(params))
    return row["c"] if row else 0


# --------------------------------------------------------------------------- #
# Phishing
# --------------------------------------------------------------------------- #
def save_phishing_scan(scan: dict) -> dict:
    s = dict(scan)
    s["scan_id"] = s.get("scan_id") or new_id("scan")
    s["created_at"] = s.get("created_at") or _now()
    with db() as conn:
        conn.execute(
            """INSERT INTO phishing_scans(scan_id, url, verdict, risk_score, reasons, redirects, created_at, scanner_ip)
               VALUES(?,?,?,?,?,?,?,?)""",
            (s["scan_id"], s.get("url", ""), s.get("verdict", "UNKNOWN"), s.get("risk_score", 0),
             _json(s.get("reasons", [])), _json(s.get("redirects", [])), s["created_at"], s.get("scanner_ip", "")),
        )
    return s


def list_phishing(limit: int = 50) -> list[dict]:
    return _fetch_all("SELECT * FROM phishing_scans ORDER BY created_at DESC LIMIT ?", (limit,))


def link_phishing_scan_to_incident(url: str, incident_id: str) -> None:
    """Backfill the incident link on a scan once its detection is correlated."""
    _execute(
        "UPDATE phishing_scans SET incident_id = ? WHERE url = ? AND incident_id = ''",
        (incident_id, url),
    )


# --------------------------------------------------------------------------- #
# Response actions
# --------------------------------------------------------------------------- #
def save_response_action(ra: dict) -> dict:
    r = dict(ra)
    r["action_id"] = r.get("action_id") or new_id("act")
    r["ts"] = r.get("ts") or _now()
    with db() as conn:
        conn.execute(
            """INSERT INTO response_actions(action_id, ts, incident_id, policy, action, reason, actor, result, detail, rollback)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (r["action_id"], r["ts"], r.get("incident_id", ""), r.get("policy", ""), r.get("action", ""),
             r.get("reason", ""), r.get("actor", "system"), r.get("result", "PENDING"), _json(r.get("detail", {})),
             r.get("rollback", "")),
        )
    return r


def list_response_actions(limit: int = 100) -> list[dict]:
    return _fetch_all("SELECT * FROM response_actions ORDER BY ts DESC LIMIT ?", (limit,))


# --------------------------------------------------------------------------- #
# Threat intel
# --------------------------------------------------------------------------- #
def get_ti(ioc_type: str, ioc_value: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM threat_intel WHERE ioc_type = ? AND ioc_value = ?", (ioc_type, ioc_value))


def upsert_ti(ioc_type: str, ioc_value: str, source: str = "local", verdict: str = "malicious") -> dict:
    now = _now()
    _execute(
        """INSERT INTO threat_intel(ioc_type, ioc_value, source, verdict, first_seen, last_seen) VALUES(?,?,?,?,?,?)
           ON CONFLICT(ioc_type, ioc_value) DO UPDATE SET last_seen=excluded.last_seen, verdict=excluded.verdict, source=excluded.source""",
        (ioc_type, ioc_value, source, verdict, now, now),
    )
    return get_ti(ioc_type, ioc_value)


def list_ti(limit: int = 200) -> list[dict]:
    return _fetch_all("SELECT * FROM threat_intel ORDER BY last_seen DESC LIMIT ?", (limit,))


# --------------------------------------------------------------------------- #
# Model state
# --------------------------------------------------------------------------- #
def save_model_state(model_name: str, version: int, trained_samples: int, params: dict, metrics: dict) -> None:
    _execute(
        "INSERT INTO model_state(model_name, version, trained_at, trained_samples, params, metrics) VALUES(?,?,?,?,?,?)",
        (model_name, version, _now(), trained_samples, _json(params), _json(metrics)),
    )


def latest_model_state(model_name: str) -> Optional[dict]:
    return _fetch_one(
        "SELECT * FROM model_state WHERE model_name = ? ORDER BY version DESC LIMIT 1", (model_name,)
    )


# --------------------------------------------------------------------------- #
# Maintenance / retention
# --------------------------------------------------------------------------- #
def apply_retention(days: int) -> dict:
    """Delete events/stats older than `days`. Never deletes incidents/audit."""
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()
    counts = {}
    with db() as conn:
        for table, col in (("events", "ts"), ("alerts", "created_at"), ("server_stats", "ts")):
            cur = conn.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff_iso,))
            counts[table] = cur.rowcount
    return counts


def stats_counts() -> dict:
    out = {}
    for table in ("users", "servers", "events", "alerts", "incidents", "audit_logs",
                  "phishing_scans", "response_actions", "threat_intel", "backup_protection",
                  "iocs", "ioc_matches", "saved_hunts", "user_risk", "asset_risk",
                  "metric_history", "response_approvals", "integration_status",
                  "api_keys", "cases", "case_incidents", "case_alerts", "case_notes",
                  "evidence", "soc_tasks"):
        out[table] = _fetch_one(f"SELECT COUNT(*) AS c FROM {table}")["c"]
    return out


# --------------------------------------------------------------------------- #
# Backup protection (defensive snapshots)
# --------------------------------------------------------------------------- #
def save_backup_protection(snapshot: dict) -> dict:
    s = dict(snapshot)
    s["snapshot_id"] = s.get("snapshot_id") or new_id("bksnap")
    s["created_at"] = s.get("created_at") or _now()
    with db() as conn:
        conn.execute(
            """INSERT INTO backup_protection(snapshot_id, incident_id, affected_files, backup_targets, created_at)
               VALUES(?,?,?,?,?)""",
            (s["snapshot_id"], s.get("incident_id", ""),
             _json(s.get("affected_files", [])), _json(s.get("backup_targets", [])),
             s["created_at"]),
        )
    return _fetch_one("SELECT * FROM backup_protection WHERE snapshot_id = ?", (s["snapshot_id"],))


def get_backup_protection(incident_id: str) -> list[dict]:
    return _fetch_all(
        "SELECT * FROM backup_protection WHERE incident_id = ? ORDER BY created_at DESC",
        (incident_id,),
    )


def list_backup_protection_all(limit: int = 100) -> list[dict]:
    return _fetch_all(
        "SELECT * FROM backup_protection ORDER BY created_at DESC LIMIT ?",
        (limit,),
    )


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
def save_report(report: dict) -> dict:
    r = dict(report)
    r["report_id"] = r.get("report_id") or new_id("rpt")
    r["created_at"] = r.get("created_at") or _now()
    with db() as conn:
        conn.execute(
            """INSERT INTO reports(report_id, report_type, title, period_start, period_end, summary, content, created_by, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (r["report_id"], r.get("report_type", "daily"), r.get("title", "SOC Report"),
             r.get("period_start", ""), r.get("period_end", ""), r.get("summary", ""),
             _json(r.get("content", {})), r.get("created_by", ""), r["created_at"]),
        )
    return get_report(r["report_id"])


def get_report(report_id: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM reports WHERE report_id = ?", (report_id,))


def list_reports(limit: int = 50, report_type: Optional[str] = None) -> list[dict]:
    clauses, params = ["1=1"], []
    if report_type:
        clauses.append("report_type = ?")
        params.append(report_type)
    params.append(limit)
    return _fetch_all(
        f"SELECT report_id, report_type, title, period_start, period_end, summary, created_by, created_at FROM reports WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT ?",
        tuple(params),
    )


def delete_report(report_id: str) -> None:
    _execute("DELETE FROM reports WHERE report_id = ?", (report_id,))


# --------------------------------------------------------------------------- #
# Notifications (in-app + notification framework)
# --------------------------------------------------------------------------- #
def save_notification(notif: dict) -> dict:
    n = dict(notif)
    n["notification_id"] = n.get("notification_id") or new_id("ntf")
    n["created_at"] = n.get("created_at") or _now()
    with db() as conn:
        conn.execute(
            """INSERT INTO notifications(notification_id, title, body, severity, channel, alert_id, incident_id, read, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (n["notification_id"], n.get("title", "Notification"), n.get("body", ""),
             n.get("severity", "medium"), n.get("channel", "in-app"),
             n.get("alert_id", ""), n.get("incident_id", ""), int(n.get("read", 0)), n["created_at"]),
        )
    return _fetch_one("SELECT * FROM notifications WHERE notification_id = ?", (n["notification_id"],))


def list_notifications(limit: int = 50, unread_only: bool = False) -> list[dict]:
    clause = "WHERE read = 0" if unread_only else ""
    return _fetch_all(f"SELECT * FROM notifications {clause} ORDER BY created_at DESC LIMIT ?", (limit,))


def count_unread_notifications() -> int:
    return _fetch_one("SELECT COUNT(*) AS c FROM notifications WHERE read = 0")["c"]


def mark_notification_read(notification_id: str) -> None:
    _execute("UPDATE notifications SET read = 1 WHERE notification_id = ?", (notification_id,))


def mark_all_notifications_read() -> int:
    with db() as conn:
        cur = conn.execute("UPDATE notifications SET read = 1 WHERE read = 0")
    return cur.rowcount


# --------------------------------------------------------------------------- #
# IOCs (indicator management)
# --------------------------------------------------------------------------- #
def save_ioc(ioc: dict) -> dict:
    i = dict(ioc)
    i["ioc_id"] = i.get("ioc_id") or new_id("ioc")
    i["first_seen"] = i.get("first_seen") or _now()
    i["last_seen"] = i.get("last_seen") or i["first_seen"]
    i["created_at"] = i.get("created_at") or _now()
    with db() as conn:
        conn.execute(
            """INSERT INTO iocs(ioc_id, ioc_type, ioc_value, verdict, confidence, source, tags, tlp,
               threat_actor, kill_chain_phase, first_seen, last_seen, created_by, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(ioc_type, ioc_value) DO UPDATE SET
                 verdict=excluded.verdict, confidence=excluded.confidence, source=excluded.source,
                 tags=excluded.tags, tlp=excluded.tlp, threat_actor=excluded.threat_actor,
                 kill_chain_phase=excluded.kill_chain_phase, last_seen=excluded.last_seen,
                 updated_at=excluded.updated_at""",
            (i["ioc_id"], i.get("ioc_type", ""), i.get("ioc_value", ""), i.get("verdict", "unknown"),
             i.get("confidence", 0.0), i.get("source", "manual"), _json(i.get("tags", [])),
             i.get("tlp", "WHITE"), i.get("threat_actor", ""), i.get("kill_chain_phase", ""),
             i["first_seen"], i["last_seen"], i.get("created_by", ""), i["created_at"], _now()),
        )
    return get_ioc_by_value(i.get("ioc_type", ""), i.get("ioc_value", ""))


def get_ioc(ioc_id: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM iocs WHERE ioc_id = ?", (ioc_id,))


def get_ioc_by_value(ioc_type: str, ioc_value: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM iocs WHERE ioc_type = ? AND ioc_value = ?", (ioc_type, ioc_value))


def list_iocs(limit: int = 200, ioc_type: Optional[str] = None,
              verdict: Optional[str] = None) -> list[dict]:
    clauses, params = ["1=1"], []
    if ioc_type:
        clauses.append("ioc_type = ?")
        params.append(ioc_type)
    if verdict:
        clauses.append("verdict = ?")
        params.append(verdict)
    params.append(limit)
    return _fetch_all(f"SELECT * FROM iocs WHERE {' AND '.join(clauses)} ORDER BY last_seen DESC LIMIT ?",
                      tuple(params))


def update_ioc(ioc_id: str, **fields) -> None:
    allowed = {"verdict", "confidence", "source", "tags", "tlp", "threat_actor",
               "kill_chain_phase", "last_seen"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(_json(v) if isinstance(v, (list, dict)) else v)
    if not sets:
        return
    sets.append("updated_at = ?")
    params.append(_now())
    params.append(ioc_id)
    _execute(f"UPDATE iocs SET {', '.join(sets)} WHERE ioc_id = ?", tuple(params))


def delete_ioc(ioc_id: str) -> None:
    _execute("DELETE FROM iocs WHERE ioc_id = ?", (ioc_id,))


def record_ioc_match(ioc_id: str, event_id: str, context: dict | None = None) -> None:
    _execute("INSERT INTO ioc_matches(ioc_id, event_id, matched_at, context) VALUES(?,?,?,?)",
             (ioc_id, event_id, _now(), _json(context or {})))


def list_ioc_matches(event_id: Optional[str] = None, limit: int = 200) -> list[dict]:
    if event_id:
        return _fetch_all(
            "SELECT * FROM ioc_matches WHERE event_id = ? ORDER BY matched_at DESC LIMIT ?",
            (event_id, limit),
        )
    return _fetch_all("SELECT * FROM ioc_matches ORDER BY matched_at DESC LIMIT ?", (limit,))


def ioc_match_counts(ioc_id: str) -> dict:
    row = _fetch_one("SELECT COUNT(*) AS c FROM ioc_matches WHERE ioc_id = ?", (ioc_id,))
    last = _fetch_one("SELECT MAX(matched_at) AS m FROM ioc_matches WHERE ioc_id = ?", (ioc_id,))
    return {"count": row["c"] if row else 0, "last_match_at": last["m"] if last else None}


# --------------------------------------------------------------------------- #
# Alert / incident history (lifecycle audit trail)
# --------------------------------------------------------------------------- #
def add_alert_history(alert_id: str, action: str, from_status: str = "", to_status: str = "",
                      actor: str = "", note: str = "") -> None:
    _execute("INSERT INTO alert_history(alert_id, action, from_status, to_status, actor, note, ts) VALUES(?,?,?,?,?,?,?)",
             (alert_id, action, from_status, to_status, actor, note, _now()))


def list_alert_history(alert_id: str, limit: int = 100) -> list[dict]:
    return _fetch_all("SELECT * FROM alert_history WHERE alert_id = ? ORDER BY ts DESC LIMIT ?",
                      (alert_id, limit))


def add_incident_history(incident_id: str, action: str, from_status: str = "", to_status: str = "",
                         actor: str = "", note: str = "") -> None:
    _execute("INSERT INTO incident_history(incident_id, action, from_status, to_status, actor, note, ts) VALUES(?,?,?,?,?,?,?)",
             (incident_id, action, from_status, to_status, actor, note, _now()))


def list_incident_history(incident_id: str, limit: int = 100) -> list[dict]:
    return _fetch_all("SELECT * FROM incident_history WHERE incident_id = ? ORDER BY ts DESC LIMIT ?",
                      (incident_id, limit))


# --------------------------------------------------------------------------- #
# Investigation notes
# --------------------------------------------------------------------------- #
def add_notes(entity_type: str, entity_id: str, note: str, author: str = "") -> dict:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO investigation_notes(entity_type, entity_id, note, author, created_at) VALUES(?,?,?,?,?)",
            (entity_type, entity_id, note, author, _now()),
        )
        nid = cur.lastrowid
    return _fetch_one("SELECT * FROM investigation_notes WHERE id = ?", (nid,))


def list_notes(entity_type: str, entity_id: str, limit: int = 100) -> list[dict]:
    return _fetch_all(
        "SELECT * FROM investigation_notes WHERE entity_type = ? AND entity_id = ? ORDER BY created_at DESC LIMIT ?",
        (entity_type, entity_id, limit),
    )


# --------------------------------------------------------------------------- #
# Saved threat hunts
# --------------------------------------------------------------------------- #
def save_hunt(hunt: dict) -> dict:
    h = dict(hunt)
    h["hunt_id"] = h.get("hunt_id") or new_id("hunt")
    h["created_at"] = h.get("created_at") or _now()
    with db() as conn:
        conn.execute(
            """INSERT INTO saved_hunts(hunt_id, name, description, query_text, query_filters, created_by, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (h["hunt_id"], h.get("name", "Untitled hunt"), h.get("description", ""),
             h.get("query_text", ""), _json(h.get("query_filters", {})), h.get("created_by", ""),
             h["created_at"], _now()),
        )
    return get_hunt(h["hunt_id"])


def get_hunt(hunt_id: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM saved_hunts WHERE hunt_id = ?", (hunt_id,))


def list_hunts(limit: int = 100) -> list[dict]:
    return _fetch_all("SELECT * FROM saved_hunts ORDER BY updated_at DESC LIMIT ?", (limit,))


def update_hunt(hunt_id: str, **fields) -> None:
    allowed = {"name", "description", "query_text", "query_filters", "last_run_at", "run_count"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(_json(v) if isinstance(v, (list, dict)) else v)
    if not sets:
        return
    sets.append("updated_at = ?")
    params.append(_now())
    params.append(hunt_id)
    _execute(f"UPDATE saved_hunts SET {', '.join(sets)} WHERE hunt_id = ?", tuple(params))


def delete_hunt(hunt_id: str) -> None:
    _execute("DELETE FROM saved_hunts WHERE hunt_id = ?", (hunt_id,))


def record_hunt_run(hunt_id: str, result_count: int, duration_ms: float) -> str:
    run_id = new_id("run")
    _execute("INSERT INTO hunt_runs(run_id, hunt_id, result_count, duration_ms, ts) VALUES(?,?,?,?,?)",
             (run_id, hunt_id, result_count, duration_ms, _now()))
    update_hunt(hunt_id, last_run_at=_now(), run_count=(get_hunt(hunt_id) or {}).get("run_count", 0) + 1)
    return run_id


def list_hunt_runs(hunt_id: str, limit: int = 50) -> list[dict]:
    return _fetch_all("SELECT * FROM hunt_runs WHERE hunt_id = ? ORDER BY ts DESC LIMIT ?",
                      (hunt_id, limit))


# --------------------------------------------------------------------------- #
# User / asset risk (computed summaries)
# --------------------------------------------------------------------------- #
def save_user_risk(username: str, score: int, level: str, factors: list,
                   events_count: int, alerts_count: int, incidents_count: int,
                   last_event_at: str = "") -> None:
    _execute(
        """INSERT INTO user_risk(username, risk_score, risk_level, risk_factors, events_count, alerts_count,
           incidents_count, last_event_at, calculated_at) VALUES(?,?,?,?,?,?,?,?,?)
           ON CONFLICT(username) DO UPDATE SET risk_score=excluded.risk_score, risk_level=excluded.risk_level,
             risk_factors=excluded.risk_factors, events_count=excluded.events_count,
             alerts_count=excluded.alerts_count, incidents_count=excluded.incidents_count,
             last_event_at=excluded.last_event_at, calculated_at=excluded.calculated_at""",
        (username, score, level, _json(factors), events_count, alerts_count, incidents_count,
         last_event_at, _now()),
    )


def get_user_risk(username: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM user_risk WHERE username = ?", (username,))


def list_user_risk(limit: int = 100, order: str = "DESC") -> list[dict]:
    return _fetch_all(f"SELECT * FROM user_risk ORDER BY risk_score {order} LIMIT ?", (limit,))


def save_asset_risk(hostname: str, score: int, level: str, factors: list,
                    events_count: int, alerts_count: int, incidents_count: int,
                    last_event_at: str = "") -> None:
    _execute(
        """INSERT INTO asset_risk(hostname, risk_score, risk_level, risk_factors, events_count, alerts_count,
           incidents_count, last_event_at, calculated_at) VALUES(?,?,?,?,?,?,?,?,?)
           ON CONFLICT(hostname) DO UPDATE SET risk_score=excluded.risk_score, risk_level=excluded.risk_level,
             risk_factors=excluded.risk_factors, events_count=excluded.events_count,
             alerts_count=excluded.alerts_count, incidents_count=excluded.incidents_count,
             last_event_at=excluded.last_event_at, calculated_at=excluded.calculated_at""",
        (hostname, score, level, _json(factors), events_count, alerts_count, incidents_count,
         last_event_at, _now()),
    )


def get_asset_risk(hostname: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM asset_risk WHERE hostname = ?", (hostname,))


def list_asset_risk(limit: int = 100, order: str = "DESC") -> list[dict]:
    return _fetch_all(f"SELECT * FROM asset_risk ORDER BY risk_score {order} LIMIT ?", (limit,))


# --------------------------------------------------------------------------- #
# Metric history (durable observability)
# --------------------------------------------------------------------------- #
def record_metric(metric_name: str, value: float, labels: dict | None = None) -> None:
    _execute("INSERT INTO metric_history(metric_name, value, labels, ts) VALUES(?,?,?,?)",
             (metric_name, value, _json(labels or {}), _now()))


def list_metrics(metric_name: Optional[str] = None, limit: int = 500,
                 hours: Optional[int] = None) -> list[dict]:
    clauses, params = ["1=1"], []
    if metric_name:
        clauses.append("metric_name = ?")
        params.append(metric_name)
    if hours:
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        clauses.append("ts >= ?")
        params.append(since)
    params.append(limit)
    return _fetch_all(f"SELECT * FROM metric_history WHERE {' AND '.join(clauses)} ORDER BY ts DESC LIMIT ?",
                      tuple(params))


def latest_metric(metric_name: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM metric_history WHERE metric_name = ? ORDER BY ts DESC LIMIT 1",
                      (metric_name,))


# --------------------------------------------------------------------------- #
# Response approvals (destructive-action approval workflow)
# --------------------------------------------------------------------------- #
def create_approval(request: dict) -> dict:
    a = dict(request)
    a["approval_id"] = a.get("approval_id") or new_id("apr")
    a["created_at"] = a.get("created_at") or _now()
    with db() as conn:
        conn.execute(
            """INSERT INTO response_approvals(approval_id, action_type, action_params, incident_id,
               requested_by, status, reason, created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (a["approval_id"], a.get("action_type", ""), _json(a.get("action_params", {})),
             a.get("incident_id", ""), a.get("requested_by", ""), a.get("status", "PENDING"),
             a.get("reason", ""), a["created_at"]),
        )
    return get_approval(a["approval_id"])


def get_approval(approval_id: str) -> Optional[dict]:
    return _fetch_one("SELECT * FROM response_approvals WHERE approval_id = ?", (approval_id,))


def list_approvals(limit: int = 100, status: Optional[str] = None) -> list[dict]:
    if status:
        return _fetch_all("SELECT * FROM response_approvals WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                          (status, limit))
    return _fetch_all("SELECT * FROM response_approvals ORDER BY created_at DESC LIMIT ?", (limit,))


def resolve_approval(approval_id: str, status: str, approved_by: str, reason: str = "") -> None:
    _execute("UPDATE response_approvals SET status = ?, approved_by = ?, reason = ?, resolved_at = ? WHERE approval_id = ?",
             (status, approved_by, reason, _now(), approval_id))


# --------------------------------------------------------------------------- #
# Integration status (commercial-ready health tracking)
# --------------------------------------------------------------------------- #
def set_integration_status(name: str, integration_type: str, status: str,
                           config: dict | None = None, error_message: str = "",
                           last_check: str = "") -> None:
    _execute(
        """INSERT INTO integration_status(name, integration_type, status, config, last_check_at, error_message, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(name) DO UPDATE SET status=excluded.status, config=excluded.config,
             last_check_at=excluded.last_check_at, error_message=excluded.error_message,
             updated_at=excluded.updated_at""",
        (name, integration_type, status, _json(config or {}), last_check or _now(),
         error_message, _now(), _now()),
    )


def list_integration_status() -> list[dict]:
    return _fetch_all("SELECT * FROM integration_status ORDER BY name")
