"""Configurable rule engine.

Rules are stored in the database and can be toggled or re-configured at
runtime without touching application code. Each rule maps to a predicate
function that receives an event plus the rule config and the event store.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from app import db
from app.engines import window as W

RULE_CATEGORIES = {
    "credential-attack": "Credential attacks (brute force, credential stuffing)",
    "network": "Network reconnaissance / scanning",
    "web-attack": "Web application attacks",
    "dos": "Denial of service",
    "malware": "Malware indicators",
    "ransomware": "Ransomware-like behavior",
    "exfiltration": "Data exfiltration",
    "privilege": "Privilege escalation",
    "insider": "Insider threat / anomalous user behavior",
    "generic": "General",
}

# --------------------------------------------------------------------------- #
# Rule predicate functions. Signature: (ev: dict, cfg: dict) -> bool
# --------------------------------------------------------------------------- #
def _rule_brute_force(ev: dict, cfg: dict) -> bool:
    src = ev.get("source_ip")
    if not src:
        return False
    failures = W.count_events_any(["auth.failed_login"], cfg.get("window_minutes", 10), "source_ip", src)
    accounts = W.distinct_values("auth.failed_login", cfg.get("window_minutes", 10), "username", "source_ip", src)
    return failures >= cfg.get("min_failures", 10) and len(accounts) >= cfg.get("unique_accounts_threshold", 2)


def _rule_distributed_login(ev: dict, cfg: dict) -> bool:
    user = ev.get("username")
    if not user:
        return False
    sources = W.distinct_values("auth.failed_login", cfg.get("window_minutes", 15), "source_ip", "username", user)
    return len(sources) >= cfg.get("min_sources", 5)


def _rule_success_after_failures(ev: dict, cfg: dict) -> bool:
    if ev.get("event_type") != "auth.successful_login":
        return False
    user = ev.get("username")
    src = ev.get("source_ip")
    if not user:
        return False
    fails = W.count_events("auth.failed_login", cfg.get("window_minutes", 30),
                           "source_ip", src) if src else 0
    user_fails = W.count_events("auth.failed_login", cfg.get("window_minutes", 30), "username", user)
    return fails >= cfg.get("min_failures", 5) or user_fails >= cfg.get("min_failures", 5)


def _rule_port_scan(ev: dict, cfg: dict) -> bool:
    src = ev.get("source_ip")
    if not src:
        return False
    ports = W.count_events_any(["net.connection", "net.connection_failed"], cfg.get("window_minutes", 5), "source_ip", src)
    return ports >= cfg.get("min_connections", 15)


def _rule_sql_injection(ev: dict, cfg: dict) -> bool:
    return bool(ev.get("details", {}).get("matched_pattern", "").startswith("sql"))


def _rule_xss(ev: dict, cfg: dict) -> bool:
    return bool(ev.get("details", {}).get("matched_pattern", "").startswith("xss"))


def _rule_command_injection(ev: dict, cfg: dict) -> bool:
    return bool(ev.get("details", {}).get("matched_pattern", "").startswith("cmd"))


def _rule_path_traversal(ev: dict, cfg: dict) -> bool:
    return bool(ev.get("details", {}).get("matched_pattern", "").startswith("traversal"))


def _rule_ddos(ev: dict, cfg: dict) -> bool:
    host = ev.get("host")
    if not host:
        return False
    rate = W.count_events("web.request", cfg.get("window_minutes", 1), "host", host)
    return rate >= cfg.get("requests_per_minute_threshold", 600)


def _rule_suspicious_executable(ev: dict, cfg: dict) -> bool:
    return ev.get("event_type") == "file.created" and ev.get("details", {}).get("suspicious", False)


def _rule_ransomware_burst(ev: dict, cfg: dict) -> bool:
    host = ev.get("host")
    if not host:
        return False
    changes = W.count_events_any(
        ["file.created", "file.modified", "file.deleted", "file.renamed"],
        cfg.get("window_minutes", 2), "host", host,
    )
    return changes >= cfg.get("min_changes", 20)


def _rule_exfiltration(ev: dict, cfg: dict) -> bool:
    if ev.get("event_type") != "net.connection":
        return False
    dest = ev.get("dest_ip")
    if not dest:
        return False
    conns = W.count_events("net.connection", cfg.get("window_minutes", 10), "dest_ip", dest)
    return conns >= cfg.get("min_connections", 30)


def _rule_sensitive_data_outbound(ev: dict, cfg: dict) -> bool:
    if ev.get("event_type") != "data.access":
        return False
    user = ev.get("username")
    if not user:
        return False
    outbound = W.count_events("net.connection", cfg.get("window_minutes", 15), "username", user)
    return outbound >= cfg.get("min_outbound", 10)


def _rule_privilege_change(ev: dict, cfg: dict) -> bool:
    return ev.get("event_type") in {"auth.privilege_change", "user.admin_grant"}


def _rule_privileged_process(ev: dict, cfg: dict) -> bool:
    return ev.get("event_type") == "process.created" and ev.get("details", {}).get("elevated", False)


def _rule_unusual_login_time(ev: dict, cfg: dict) -> bool:
    if ev.get("event_type") != "auth.successful_login":
        return False
    try:
        hour = int(ev.get("ts", "")[11:13])
    except Exception:
        return False
    return not (cfg.get("start_hour", 6) <= hour < cfg.get("end_hour", 22))


def _rule_phishing_malicious(ev: dict, cfg: dict) -> bool:
    """A URL analysis verdict that reached the MALICIOUS threshold."""
    if ev.get("event_type") != "phishing.detected":
        return False
    details = ev.get("details") or {}
    return details.get("verdict") == "MALICIOUS"


def _rule_field_equals(ev: dict, cfg: dict) -> bool:
    """Generic config-driven predicate: ev[field] == value."""
    field = cfg.get("field", "")
    value = cfg.get("value")
    if not field or value is None:
        return False
    return str(ev.get(field, "")) == str(value)


def _rule_count_events_gt(ev: dict, cfg: dict) -> bool:
    """Generic config-driven predicate: count of event_type (grouped by key)
    within the window exceeds the configured threshold."""
    event_type = cfg.get("event_type")
    key_field = cfg.get("key_field", "source_ip")
    key = ev.get(key_field)
    if not event_type or not key:
        return False
    count = W.count_events(event_type, cfg.get("window_minutes", 10), key_field, key)
    return count >= cfg.get("min_count", 10)


# rule_id -> predicate
PREDICATES = {
    "brute_force_velocity": _rule_brute_force,
    "distributed_login_attempts": _rule_distributed_login,
    "success_after_failures": _rule_success_after_failures,
    "port_scan": _rule_port_scan,
    "sql_injection": _rule_sql_injection,
    "xss": _rule_xss,
    "command_injection": _rule_command_injection,
    "path_traversal": _rule_path_traversal,
    "ddos_request_flood": _rule_ddos,
    "suspicious_executable": _rule_suspicious_executable,
    "ransomware_file_burst": _rule_ransomware_burst,
    "exfiltration_connection_flood": _rule_exfiltration,
    "sensitive_data_outbound": _rule_sensitive_data_outbound,
    "privilege_change": _rule_privilege_change,
    "privileged_process_creation": _rule_privileged_process,
    "unusual_login_time": _rule_unusual_login_time,
    "phishing_malicious": _rule_phishing_malicious,
    # Generic config-driven predicates (enables API-created rules).
    "field_equals": _rule_field_equals,
    "count_events_gt": _rule_count_events_gt,
}

# Predicates that require a code implementation (cannot be created via API).
CODE_ONLY_PREDICATES = {k for k in PREDICATES if k not in {"field_equals", "count_events_gt"}}

# --------------------------------------------------------------------------- #
# Default rules (shipped with the product; can be edited at runtime)
# --------------------------------------------------------------------------- #
def default_rules() -> list[dict]:
    return [
        {
            "rule_id": "brute_force_velocity",
            "name": "Brute force: excessive failed logins from one source",
            "description": "More than the configured number of failed login attempts from a single source IP within the window.",
            "category": "credential-attack",
            "enabled": True, "severity": "high",
            "mitre": ["T1110", "T1110.001", "T1110.003"],
            "config": {"window_minutes": 10, "min_failures": 10, "unique_accounts_threshold": 2},
        },
        {
            "rule_id": "distributed_login_attempts",
            "name": "Distributed login attempts against one account",
            "description": "A single account receiving failed logins from many distinct source IPs.",
            "category": "credential-attack",
            "enabled": True, "severity": "high",
            "mitre": ["T1110", "T1110.004"],
            "config": {"window_minutes": 15, "min_sources": 5},
        },
        {
            "rule_id": "success_after_failures",
            "name": "Successful login after repeated failures",
            "description": "A successful authentication that immediately follows a burst of failures for the same account or source.",
            "category": "credential-attack",
            "enabled": True, "severity": "high",
            "mitre": ["T1078", "T1110"],
            "config": {"window_minutes": 30, "min_failures": 5},
        },
        {
            "rule_id": "port_scan",
            "name": "Port scanning / host discovery",
            "description": "A single source contacting many distinct ports in a short window.",
            "category": "network",
            "enabled": True, "severity": "medium",
            "mitre": ["T1046", "T1040"],
            "config": {"window_minutes": 5, "min_connections": 15},
        },
        {
            "rule_id": "sql_injection",
            "name": "SQL injection pattern in request",
            "description": "Request contains SQL metacharacter patterns consistent with injection attempts.",
            "category": "web-attack",
            "enabled": True, "severity": "high",
            "mitre": ["T1190", "T1189"],
            "config": {},
        },
        {
            "rule_id": "xss",
            "name": "Cross-site scripting pattern in request",
            "description": "Request contains script injection patterns.",
            "category": "web-attack",
            "enabled": True, "severity": "medium",
            "mitre": ["T1059.007", "T1189"],
            "config": {},
        },
        {
            "rule_id": "command_injection",
            "name": "Command injection pattern in request",
            "description": "Request contains operating-system command injection patterns.",
            "category": "web-attack",
            "enabled": True, "severity": "high",
            "mitre": ["T1059", "T1190"],
            "config": {},
        },
        {
            "rule_id": "path_traversal",
            "name": "Path traversal pattern in request",
            "description": "Request attempts to access files outside intended application paths.",
            "category": "web-attack",
            "enabled": True, "severity": "medium",
            "mitre": ["T1083", "T1005"],
            "config": {},
        },
        {
            "rule_id": "ddos_request_flood",
            "name": "Request flood against a host",
            "description": "Request volume against a single host far exceeds the configured threshold for the window.",
            "category": "dos",
            "enabled": True, "severity": "high",
            "mitre": ["T1498", "T1499"],
            "config": {"window_minutes": 1, "requests_per_minute_threshold": 600},
        },
        {
            "rule_id": "suspicious_executable",
            "name": "Suspicious executable created",
            "description": "An executable file with suspicious characteristics was created.",
            "category": "malware",
            "enabled": True, "severity": "high",
            "mitre": ["T1204", "T1059"],
            "config": {},
        },
        {
            "rule_id": "ransomware_file_burst",
            "name": "Ransomware-like file modification burst",
            "description": "A large number of file create/modify/delete events on one host within a short window.",
            "category": "ransomware",
            "enabled": True, "severity": "critical",
            "mitre": ["T1486", "T1490"],
            "config": {"window_minutes": 2, "min_changes": 20},
        },
        {
            "rule_id": "exfiltration_connection_flood",
            "name": "Data exfiltration: connection flood to external host",
            "description": "A single external destination receiving a high volume of connections.",
            "category": "exfiltration",
            "enabled": True, "severity": "high",
            "mitre": ["T1041", "T1048"],
            "config": {"window_minutes": 10, "min_connections": 30},
        },
        {
            "rule_id": "sensitive_data_outbound",
            "name": "Sensitive data access followed by outbound transfers",
            "description": "A user accessing sensitive data then generating many outbound connections.",
            "category": "exfiltration",
            "enabled": True, "severity": "critical",
            "mitre": ["T1005", "T1041"],
            "config": {"window_minutes": 15, "min_outbound": 10},
        },
        {
            "rule_id": "privilege_change",
            "name": "Privilege change",
            "description": "Account privileges were changed or an admin was granted.",
            "category": "privilege",
            "enabled": True, "severity": "medium",
            "mitre": ["T1078", "T1548"],
            "config": {},
        },
        {
            "rule_id": "privileged_process_creation",
            "name": "Privileged process creation",
            "description": "A process was created with elevated privileges.",
            "category": "privilege",
            "enabled": True, "severity": "medium",
            "mitre": ["T1548", "T1059"],
            "config": {},
        },
        {
            "rule_id": "unusual_login_time",
            "name": "Login outside normal working hours",
            "description": "Successful login outside the configured working-hours window.",
            "category": "insider",
            "enabled": True, "severity": "low",
            "mitre": ["T1078"],
            "config": {"start_hour": 6, "end_hour": 22},
        },
        {
            "rule_id": "phishing_malicious",
            "name": "Malicious URL detected",
            "description": "A URL analysis returned a MALICIOUS verdict, indicating a probable phishing attempt.",
            "category": "phishing",
            "enabled": True, "severity": "high",
            "mitre": ["T1566"],
            "config": {},
        },
    ]


def seed_default_rules() -> int:
    count = 0
    for rule in default_rules():
        db.upsert_rule(rule)
        count += 1
    return count


def is_rule_enabled(rule_id: str) -> bool:
    """Check the persisted enabled flag (used by structural detectors)."""
    rule = db.get_rule(rule_id)
    return bool(rule and rule.get("enabled", 1))


def evaluate_rule_against_history(rule: dict, minutes: int = 60, limit: int = 500,
                                  event_type: str | None = None) -> dict:
    """Run a rule's predicate against historical events (test mode)."""
    pred = PREDICATES.get(rule["rule_id"])
    if pred is None:
        return {"matches": [], "matched": 0, "evaluated": 0, "error": f"No predicate for rule_id '{rule['rule_id']}'"}
    events = db.query_events(minutes=minutes, limit=limit)
    if event_type:
        events = [e for e in events if e.get("event_type") == event_type]
    cfg = rule.get("config") or {}
    matches = []
    for ev in events:
        try:
            if pred(ev, cfg):
                matches.append({
                    "event_id": ev.get("event_id"),
                    "ts": ev.get("ts"),
                    "event_type": ev.get("event_type"),
                    "host": ev.get("host"),
                    "source_ip": ev.get("source_ip"),
                    "username": ev.get("username"),
                    "severity": ev.get("severity"),
                })
        except Exception:
            continue
    return {"matches": matches, "matched": len(matches), "evaluated": len(events)}


# --------------------------------------------------------------------------- #
# Rule engine
# --------------------------------------------------------------------------- #
class RuleEngine:
    def __init__(self):
        self._cache: dict = {}
        self._cache_ts = 0.0

    def rules(self, refresh: bool = False) -> list[dict]:
        import time
        now = time.time()
        if refresh or not self._cache or now - self._cache_ts > 10:
            rules = db.list_rules(enabled_only=True)
            self._cache = {r["rule_id"]: r for r in rules}
            self._cache_ts = now
        return list(self._cache.values())

    def evaluate(self, ev: dict) -> list[dict]:
        """Return detection dicts for every rule triggered by this event."""
        detections = []
        for rule in self.rules():
            pred = PREDICATES.get(rule["rule_id"])
            if pred is None:
                continue
            cfg = rule.get("config") or {}
            try:
                if pred(ev, cfg):
                    detections.append(self._build_detection(rule, ev))
            except Exception:
                continue
        return detections

    def _build_detection(self, rule: dict, ev: dict) -> dict:
        return {
            "event_id": ev.get("event_id"),
            "rule_id": rule["rule_id"],
            "rule_name": rule["name"],
            "description": rule["description"],
            "category": rule["category"],
            "severity": rule["severity"],
            "mitre": rule.get("mitre", []),
            "source_ip": ev.get("source_ip", ""),
            "dest_ip": ev.get("dest_ip", ""),
            "host": ev.get("host", ""),
            "username": ev.get("username", ""),
        }


rule_engine = RuleEngine()
