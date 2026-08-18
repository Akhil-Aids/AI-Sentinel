"""SQLite persistence for AI Sentinel.

All security data is stored durably across restarts (no in-memory-only storage).
Indexes are created for high-volume event/alert/incident queries.
Thread-safety: a single module-level connection is guarded by a lock; FastAPI
runs routes in a thread pool, and a short-lived write lock is acceptable for a
single-node deployment.
"""
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
    detail TEXT DEFAULT '{}'
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
"""


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
    conn.commit()


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #
def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    for key in ("details", "raw", "mitre", "timeline", "event_ids", "evidence",
                "detection_rules", "recommended_actions", "actions_taken",
                "reasons", "redirects", "params", "metrics", "detail", "tags", "config", "snapshot"):
        if key in d:
            d[key] = _loads(d[key], [] if key not in ("details", "raw", "params", "metrics", "detail", "config", "tags", "snapshot") else {})
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
    return _fetch_all("SELECT id, username, role, full_name, is_active, created_at, last_login_at FROM users ORDER BY username")


def update_user(user_id: int, **fields) -> None:
    allowed = {"role", "full_name", "is_active", "password_hash", "last_login_at"}
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
def log_audit(actor: str, action: str, result: str = "SUCCESS", target: str = "",
              detail: dict | None = None, role: str = "", ip: str = "") -> None:
    _execute(
        "INSERT INTO audit_logs(ts, actor, actor_role, action, target, result, ip, detail) VALUES(?,?,?,?,?,?,?,?)",
        (_now(), actor, role, action, target, result, ip, _json(detail or {})),
    )


def list_audit(limit: int = 200, actor: Optional[str] = None) -> list[dict]:
    if actor:
        return _fetch_all("SELECT * FROM audit_logs WHERE actor = ? ORDER BY ts DESC LIMIT ?", (actor, limit))
    return _fetch_all("SELECT * FROM audit_logs ORDER BY ts DESC LIMIT ?", (limit,))


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
                  "phishing_scans", "response_actions", "threat_intel"):
        out[table] = _fetch_one(f"SELECT COUNT(*) AS c FROM {table}")["c"]
    return out
