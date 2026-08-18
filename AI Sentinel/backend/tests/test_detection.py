"""Detection pipeline unit tests: window queries, rule predicates, web attacks, correlator."""
from datetime import datetime, timezone

from app import db
from app.correlate import correlator
from app.engines import build_detection_engine
from app.engines.rules import rule_engine
from app.engines import window as W
from app.pipeline.normalize import normalize_raw


def _now():
    return datetime.now(timezone.utc).isoformat()


def _reset():
    db._execute("DELETE FROM events")
    db._execute("DELETE FROM incident_events")
    db._execute("DELETE FROM incidents")
    db._execute("DELETE FROM alerts")


def _ingest(event_type, source_ip=None, username=None, host=None, ts=None, details=None, **extra):
    ev = {
        "ts": ts or _now(),
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username,
        "host": host,
        "details": details or {},
        **extra,
    }
    return db.save_event(normalize_raw(ev, source="test"))


def test_window_count_and_distinct():
    _reset()
    for i in range(4):
        _ingest("auth.failed_login", source_ip="10.0.0.1", username=f"u{i % 2}")
    assert W.count_events_any(["auth.failed_login"], 10, "source_ip", "10.0.0.1") == 4
    assert len(W.distinct_values("auth.failed_login", 10, "username", "source_ip", "10.0.0.1")) == 2
    assert W.count_events("auth.failed_login", 10, "source_ip", "9.9.9.9") == 0


def test_brute_force_predicate():
    _reset()
    for i in range(12):
        _ingest("auth.failed_login", source_ip="10.0.0.2", username=f"u{i % 3}")
    ev = _ingest("auth.failed_login", source_ip="10.0.0.2", username="u3")
    cfg = {"window_minutes": 10, "min_failures": 10, "unique_accounts_threshold": 2}
    res = rule_engine.evaluate(ev)
    assert any(d["rule_id"] == "brute_force_velocity" for d in res)


def test_sql_injection_structural_detection():
    engine = build_detection_engine(ml=None)
    ev = {
        "event_id": "evt-test-1",
        "event_type": "web.request",
        "source_ip": "198.51.100.4",
        "details": {"method": "GET", "path": "/products", "query": "category=1' OR '1'='1", "body": ""},
    }
    res = engine.analyze(ev)
    kinds = [d["rule_id"] for d in res["detections"]]
    assert "sql_injection" in kinds


def test_xss_structural_detection():
    engine = build_detection_engine(ml=None)
    ev = {
        "event_id": "evt-test-2",
        "event_type": "web.request",
        "details": {"method": "POST", "path": "/comment", "query": "",
                    "body": "<script>alert(1)</script>"},
    }
    res = engine.analyze(ev)
    assert "xss" in [d["rule_id"] for d in res["detections"]]


def test_correlator_creates_incident_with_risk():
    _reset()
    ev = db.save_event(normalize_raw({
        "ts": _now(), "event_type": "auth.failed_login", "source_ip": "10.0.0.9",
        "username": "victim", "details": {"reason": "brute force"},
    }, source="test"))
    detection = {
        "rule_id": "brute_force_velocity",
        "rule_name": "Brute force test",
        "category": "credential-attack",
        "severity": "high",
        "mitre": ["T1110"],
        "source_ip": "10.0.0.9",
        "username": "victim",
    }
    inc = correlator.correlate(detection, ev, risk_score=60)
    assert inc["risk_score"] == 60
    assert inc["category"] == "credential-attack"
    assert ev["event_id"] in inc["event_ids"]


def test_correlator_dedups_same_campaign():
    _reset()
    ev1 = db.save_event(normalize_raw({
        "ts": _now(), "event_type": "auth.failed_login", "source_ip": "10.0.0.9", "username": "a"}, source="test"))
    detection = {
        "rule_id": "brute_force_velocity", "rule_name": "Brute force test",
        "category": "credential-attack", "severity": "high", "source_ip": "10.0.0.9",
    }
    inc1 = correlator.correlate(detection, ev1, risk_score=60)
    ev2 = db.save_event(normalize_raw({
        "ts": _now(), "event_type": "auth.failed_login", "source_ip": "10.0.0.9", "username": "b"}, source="test"))
    inc2 = correlator.correlate(detection, ev2, risk_score=60)
    assert inc1["incident_id"] == inc2["incident_id"]

