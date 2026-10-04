"""Regression tests for two silent pipeline defects found during live evaluation.

H1 -- `correlate.Correlator._find_matching` referenced an undefined name `c`
while building the cross-family "related" set. The ``NameError`` propagated out
of correlation, and the pipeline swallowed it into a ``pipeline.process_error``
row. Net effect: detections in a *different attack family* than the open
incident were silently dropped instead of being merged. It only triggered when
two families shared a correlation key but had different categories, so
same-family tests never reached it.

H2 -- ``db.update_incident`` filtered writes through a column allow-list that
omitted the denormalized columns correlation merges depend on (``timeline``,
``mitre``, ``risk_score``, ``category``, ``event_ids``). A merge appeared to
succeed -- ``correlate`` returned a refreshed incident -- but the accumulated
evidence was discarded on write, so an incident permanently displayed only its
first constituent event.

Both defects share a failure mode: no exception reached the caller, so no test
or assertion fired. These tests assert on the *persisted* result rather than on
return values.
"""
from datetime import datetime, timezone

from app import db
from app.correlate import correlator


def _now():
    return datetime.now(timezone.utc).isoformat()


def _reset():
    db._execute("DELETE FROM incident_events")
    db._execute("DELETE FROM incidents")
    db._execute("DELETE FROM events")


def _event(event_type, host, source_ip="198.51.100.7"):
    return db.save_event({
        "ts": _now(),
        "event_type": event_type,
        "source_ip": source_ip,
        "host": host,
        "details": {},
    })


def _detection(rule_id, category, mitre, host, source_ip="198.51.100.7"):
    return {
        "rule_id": rule_id,
        "rule_name": f"rule {rule_id}",
        "category": category,
        "severity": "high",
        "mitre": list(mitre),
        "host": host,
        "source_ip": source_ip,
    }


# --------------------------------------------------------------------------- #
# H1 -- cross-family correlation must merge, not raise and drop the detection
# --------------------------------------------------------------------------- #

def test_h1_exfiltration_merges_into_malware_incident():
    """The exact branch that raised NameError: two different families, same host."""
    _reset()
    first = correlator.correlate(
        _detection("suspicious_executable", "malware", ["T1204"], "workstation-7"),
        _event("process.created", "workstation-7"),
        risk_score=70,
    )

    # Pre-fix this call raised `NameError: name 'c' is not defined`.
    second = correlator.correlate(
        _detection("large_data_transfer", "exfiltration", ["T1041"], "workstation-7"),
        _event("network.connection", "workstation-7"),
        risk_score=80,
    )

    assert second["incident_id"] == first["incident_id"], (
        "cross-family detection must merge into the open incident, not create a new one"
    )
    categories = second["category"].split(";")
    assert "malware" in categories and "exfiltration" in categories


def test_h1_ransomware_merges_into_exfiltration_incident():
    """The sibling branch of the same `related`-set condition."""
    _reset()
    first = correlator.correlate(
        _detection("large_data_transfer", "exfiltration", ["T1041"], "fileserver-2"),
        _event("network.connection", "fileserver-2"),
        risk_score=75,
    )
    second = correlator.correlate(
        _detection("mass_file_encryption", "ransomware", ["T1486"], "fileserver-2"),
        _event("file.modified", "fileserver-2"),
        risk_score=95,
    )
    assert second["incident_id"] == first["incident_id"]
    categories = second["category"].split(";")
    assert "exfiltration" in categories and "ransomware" in categories


def test_h1_unrelated_family_still_opens_a_new_incident():
    """Negative control: the merge must not become unconditional."""
    _reset()
    first = correlator.correlate(
        _detection("brute_force_velocity", "credential-attack", ["T1110"], "jumpbox-1"),
        _event("auth.failed_login", "jumpbox-1"),
        risk_score=60,
    )
    second = correlator.correlate(
        _detection("suspicious_executable", "malware", ["T1204"], "jumpbox-1"),
        _event("process.created", "jumpbox-1"),
        risk_score=70,
    )
    assert second["incident_id"] != first["incident_id"]


# --------------------------------------------------------------------------- #
# H2 -- update_incident must persist the correlation merge columns
# --------------------------------------------------------------------------- #

def test_h2_update_incident_persists_merge_columns():
    """Direct allow-list test: every column correlation writes must survive.

    `update_incident` overwrites rather than appends -- the correlator reads the
    current value and passes the merged list -- so this asserts the written
    value is what comes back. A dropped write would leave the create-time row
    instead, which has different keys, so the comparison is still meaningful.
    """
    _reset()
    inc = correlator.correlate(
        _detection("suspicious_executable", "malware", ["T1204"], "workstation-9"),
        _event("process.created", "workstation-9"),
        risk_score=70,
    )
    original_event_id = inc["event_ids"][0]

    db.update_incident(
        inc["incident_id"],
        timeline=[{"time": _now(), "event_id": "evt-x", "description": "second entry"}],
        mitre=["T1204", "T1059", "T1041"],
        risk_score=88,
        category="malware;exfiltration",
        event_ids=[original_event_id, "evt-x"],
    )

    stored = db.get_incident(inc["incident_id"])
    assert [e.get("event_id") for e in stored["timeline"]] == ["evt-x"], (
        "timeline column did not persist"
    )
    assert stored["mitre"] == ["T1204", "T1059", "T1041"], "mitre column did not persist"
    assert stored["risk_score"] == 88, "risk_score column did not persist"
    assert stored["category"] == "malware;exfiltration", "category column did not persist"
    assert stored["event_ids"] == [original_event_id, "evt-x"], (
        "event_ids column did not persist"
    )


def test_h2_merge_accumulates_timeline_mitre_and_events():
    """End-to-end: a two-event incident must retain both events' evidence."""
    _reset()
    first = correlator.correlate(
        _detection("suspicious_executable", "malware", ["T1204"], "workstation-3"),
        _event("process.created", "workstation-3"),
        risk_score=70,
    )
    second = correlator.correlate(
        _detection("large_data_transfer", "exfiltration", ["T1041"], "workstation-3"),
        _event("network.connection", "workstation-3"),
        risk_score=80,
    )

    assert second["incident_id"] == first["incident_id"]
    assert len(second["timeline"]) == 2, "incident timeline lost an entry on merge"
    assert len(second["event_ids"]) == 2, "incident lost a linked event on merge"

    # malware create-path MITRE is [T1204, T1059]; merge adds T1041.
    assert sorted(second["mitre"]) == ["T1041", "T1059", "T1204"], (
        "incident MITRE techniques were not unioned across the merge"
    )

    stored = db.get_incident(second["incident_id"])
    assert len(stored["timeline"]) == 2, "merge was not durably persisted"
    assert len(stored["event_ids"]) == 2


def test_h2_merge_does_not_duplicate_techniques():
    """MITRE union must deduplicate; repeated merges must not inflate the list."""
    _reset()
    correlator.correlate(
        _detection("suspicious_executable", "malware", ["T1204"], "workstation-4"),
        _event("process.created", "workstation-4"),
        risk_score=70,
    )
    result = correlator.correlate(
        _detection("another_malware_rule", "malware", ["T1204"], "workstation-4"),
        _event("process.created", "workstation-4"),
        risk_score=70,
    )
    assert sorted(result["mitre"]) == ["T1059", "T1204"], "duplicate MITRE technique retained"


def test_h2_risk_score_is_monotonic_across_merges():
    """Risk must escalate with a higher-scoring merge but never regress downward."""
    _reset()
    correlator.correlate(
        _detection("suspicious_executable", "malware", ["T1204"], "workstation-5"),
        _event("process.created", "workstation-5"),
        risk_score=90,
    )
    escalated = correlator.correlate(
        _detection("large_data_transfer", "exfiltration", ["T1041"], "workstation-5"),
        _event("network.connection", "workstation-5"),
        risk_score=95,
    )
    assert escalated["risk_score"] >= 90, "risk_score regressed on a high-risk merge"

    _reset()
    correlator.correlate(
        _detection("large_data_transfer", "exfiltration", ["T1041"], "workstation-6"),
        _event("network.connection", "workstation-6"),
        risk_score=90,
    )
    lower = correlator.correlate(
        _detection("suspicious_executable", "malware", ["T1204"], "workstation-6"),
        _event("process.created", "workstation-6"),
        risk_score=10,
    )
    assert lower["risk_score"] >= 90, "risk_score was downgraded by a low-risk merge"
