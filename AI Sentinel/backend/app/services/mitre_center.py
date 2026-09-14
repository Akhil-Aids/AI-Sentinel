"""MITRE ATT&CK coverage engine, detection gap analysis and post-incident review.

Everything is derived from the real corpus: enabled/disabled detection rules,
their MITRE technique tags, and observed incident techniques. Techniques that
exist in neither rules nor incidents are simply NOT reported (we never guess
coverage the platform does not actually provide).
"""
from app import db

# Curated tactic labels for the technique families shipped / observed commonly.
# Unknown technique codes are reported as "Unclassified" — never invented.
TACTIC_MAP = {
    "T1005": "Collection", "T1021": "Lateral Movement", "T1036": "Defense Evasion",
    "T1041": "Exfiltration", "T1053": "Persistence", "T1055": "Defense Evasion",
    "T1059": "Execution", "T1071": "Command and Control", "T1078": "Initial Access",
    "T1082": "Discovery", "T1083": "Discovery", "T1090": "Command and Control",
    "T1105": "Command and Control", "T1110": "Credential Access", "T1133": "Persistence",
    "T1486": "Impact", "T1490": "Impact", "T1505": "Persistence", "T1566": "Initial Access",
    "T1567": "Exfiltration", "T1568": "Command and Control", "T1583": "Resource Development",
    "T1190": "Initial Access", "T1213": "Collection", "T1069": "Discovery",
    "T1070": "Defense Evasion", "T1204": "Execution", "T1222": "Defense Evasion",
    "T1499": "Impact", "T1543": "Persistence", "T1547": "Persistence", "T1562": "Defense Evasion",
}


def _technique_id(tag: str) -> str:
    tag = tag.strip().upper()
    if not tag.startswith("T"):
        return ""
    return ".".join(tag.split(".")[:2])


def _tactic(tech: str) -> str:
    return TACTIC_MAP.get(tech, "Unclassified")


def coverage() -> dict:
    rules = db.list_rules()
    incidents = db.list_incidents(limit=500)
    alerts = db.list_alerts(limit=2000)

    techniques: dict[str, dict] = {}
    # Rule-side coverage.
    for rule in rules:
        for raw in rule.get("mitre", []) or []:
            tech = _technique_id(raw)
            if not tech:
                continue
            entry = techniques.setdefault(tech, {
                "technique": tech, "tactic": _tactic(tech), "rules": set(), "enabled_rules": set(),
                "disabled_rules": set(), "incidents": 0, "alerts": 0, "alert_ids": set(),
            })
            entry["rules"].add(rule["rule_id"])
            if rule.get("enabled"):
                entry["enabled_rules"].add(rule["rule_id"])
            else:
                entry["disabled_rules"].add(rule["rule_id"])
    # Incident-side observed techniques.
    for inc in incidents:
        for raw in inc.get("mitre", []) or []:
            tech = _technique_id(raw)
            if not tech:
                continue
            entry = techniques.setdefault(tech, {
                "technique": tech, "tactic": _tactic(tech), "rules": set(), "enabled_rules": set(),
                "disabled_rules": set(), "incidents": 0, "alerts": 0, "alert_ids": set(),
            })
            entry["incidents"] += 1
    # Alert-side observed techniques.
    for alert in alerts:
        for raw in alert.get("mitre", []) or []:
            tech = _technique_id(raw)
            if not tech:
                continue
            entry = techniques.setdefault(tech, {
                "technique": tech, "tactic": _tactic(tech), "rules": set(), "enabled_rules": set(),
                "disabled_rules": set(), "incidents": 0, "alerts": 0, "alert_ids": set(),
            })
            entry["alerts"] += 1
            entry["alert_ids"].add(alert.get("alert_id", ""))

    rows = []
    for tech, e in sorted(techniques.items()):
        enabled = len(e["enabled_rules"]) > 0
        observed = (e["incidents"] + e["alerts"]) > 0
        if enabled and observed:
            status = "VERIFIED_LIVE"
        elif enabled:
            status = "DETECTING"
        elif e["rules"]:
            status = "RULES_DISABLED"
        else:
            status = "OBSERVED_NO_RULES"
        rows.append({
            "technique": tech,
            "tactic": e["tactic"],
            "status": status,
            "enabled_rules": sorted(e["enabled_rules"]),
            "disabled_rules": sorted(e["disabled_rules"]),
            "incidents": e["incidents"],
            "alerts": e["alerts"],
        })
    return {
        "coverage": {
            "techniques_covered": sum(1 for r in rows if r["status"] in ("VERIFIED_LIVE", "DETECTING")),
            "techniques_monitored": len(rows),
            "verified_live": sum(1 for r in rows if r["status"] == "VERIFIED_LIVE"),
            "detecting_only": sum(1 for r in rows if r["status"] == "DETECTING"),
            "rules_disabled": sum(1 for r in rows if r["status"] == "RULES_DISABLED"),
            "observed_no_rules": sum(1 for r in rows if r["status"] == "OBSERVED_NO_RULES"),
            "tactics_covered": sorted({r["tactic"] for r in rows if r["status"] != "OBSERVED_NO_RULES"}),
        },
        "techniques": rows,
        "gap_recommendations": gap_recommendations(rows),
    }


def gap_recommendations(rows: list[dict]) -> list[dict]:
    recs = []
    for r in rows:
        if r["status"] == "OBSERVED_NO_RULES":
            recs.append({
                "priority": "high",
                "type": "missing_detection",
                "technique": r["technique"],
                "tactic": r["tactic"],
                "recommendation": f"Technique {r['technique']} observed {r['incidents']} incident(s) / {r['alerts']} alert(s) with no detection rule — create and enable a rule for it.",
                "observed": {"incidents": r["incidents"], "alerts": r["alerts"]},
            })
        elif r["status"] == "RULES_DISABLED":
            recs.append({
                "priority": "medium",
                "type": "rule_disabled",
                "technique": r["technique"],
                "tactic": r["tactic"],
                "recommendation": f"Rules for {r['technique']} exist but are disabled: {', '.join(r['disabled_rules'])} — review and enable.",
            })
    # Category-level gaps: incidents whose category has no enabled rule at all.
    rules = db.list_rules()
    enabled_categories = {r.get("category") for r in rules if r.get("enabled")}
    category_gaps = {}
    for inc in db.list_incidents(limit=1000):
        cat = inc.get("category", "") or "uncategorized"
        if cat not in enabled_categories:
            category_gaps.setdefault(cat, 0)
            category_gaps[cat] += 1
    for cat, count in sorted(category_gaps.items(), key=lambda x: -x[1])[:8]:
        if count >= 2:
            recs.append({
                "priority": "medium",
                "type": "category_coverage",
                "category": cat,
                "recommendation": f"{count} incidents categorised as '{cat}' have no enabled detection rule covering that category.",
                "incidents": count,
            })
    recs.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x.get("priority"), 3))
    return recs


# --------------------------------------------------------------------------- #
# Post-incident review
# --------------------------------------------------------------------------- #
def produce_review(incident: dict) -> dict:
    if not incident:
        return {"status": "NO_DATA"}
    timeline = incident.get("timeline", []) or []
    history = db.list_incident_history(incident["incident_id"], limit=100)
    evidence = db.list_evidence(incident_id=incident["incident_id"])
    tasks = db.list_tasks(incident_id=incident["incident_id"])
    detection_rules = [r for r in (incident.get("detection_rules", []) or [])]
    findings = []
    recommendations = []

    def _rule_state(rule_id: str) -> str:
        rule = _lookup_rule(rule_id)
        if not rule:
            return "unknown"
        return "enabled" if rule.get("enabled") else "disabled"

    disabled_rules = [rid for rid in detection_rules if _rule_state(rid) == "disabled"]
    if disabled_rules:
        findings.append({"type": "rule_disabled", "detail": f"Detected by now-disabled rule(s): {', '.join(disabled_rules)}"})
        recommendations.append("Re-enable or re-certify the rules that produced the detection to keep coverage honest.")

    if not evidence:
        findings.append({"type": "no_evidence", "detail": "No evidence records attached to this incident."})
        recommendations.append("Preserve evidence (artifacts, logs, network captures) before cleanup.")

    open_tasks = [t for t in tasks if t.get("status") in ("TODO", "IN_PROGRESS")]
    if open_tasks:
        findings.append({"type": "open_tasks", "detail": f"{len(open_tasks)} remediation task(s) still open."})
        recommendations.append("Close remediation tasks; verify containment before declaring recovery.")

    if not history:
        findings.append({"type": "no_history", "detail": "Incident has no lifecycle history (no triage/status changes)."})
        recommendations.append("Document triage and containment actions in the incident history.")

    if not detection_rules:
        findings.append({"type": "no_detection_rule", "detail": "Incident has no linked detection rule."})
        recommendations.append("Link the incident to its generating detection rule for reproducibility.")

    phase_metrics = _phase_metrics(incident)
    return {
        "status": "COMPLETE",
        "incident_id": incident["incident_id"],
        "severity": incident.get("severity"),
        "category": incident.get("category", ""),
        "timeline_events": len(timeline),
        "history_entries": len(history),
        "evidence_count": len(evidence),
        "task_counts": {"total": len(tasks), "open": len(open_tasks), "done": sum(1 for t in tasks if t.get("status") == "DONE")},
        "detection_rules": detection_rules,
        "phase_metrics": phase_metrics,
        "findings": findings,
        "recommendations": recommendations,
        "kill_chain_stage": _kill_chain_stage(incident),
    }


def _lookup_rule(rule_id: str):
    for r in db.list_rules():
        if r["rule_id"] == rule_id:
            return r
    return None


def _phase_metrics(incident: dict) -> dict:
    created = _to_epoch(incident.get("created_at"))
    ack = _to_epoch(incident.get("acknowledged_at"))
    resolved = _to_epoch(incident.get("resolved_at"))
    now = _now_epoch()
    return {
        "detect_to_ack_seconds": (ack - created) if ack and created else None,
        "detect_to_contain_seconds": max(0.0, (now - created)) if not resolved else None,
        "detect_to_resolve_seconds": (resolved - created) if resolved and created else None,
    }


def _kill_chain_stage(incident: dict) -> str:
    status = incident.get("status", "NEW")
    if status in ("RESOLVED", "FALSE_POSITIVE"):
        return "RECOVERED" if status == "RESOLVED" else "DISMISSED"
    if status == "CONTAINED":
        return "CONTAINED"
    if status == "INVESTIGATING":
        return "ANALYSIS"
    return "DETECTED"


def _to_epoch(value) -> float | None:
    from datetime import datetime, timezone
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except Exception:
        return None


def _now_epoch() -> float:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).timestamp()