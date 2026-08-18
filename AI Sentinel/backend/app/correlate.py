"""Event correlation -> incidents.

Groups related detections into a single incident instead of creating an alert
for every event. Correlation keys: source IP, username, and host, within a
time window and by attack family (progression-aware). MITRE ATT&CK mappings
are assigned only when the corresponding rule/detection carried evidence.
"""
from datetime import datetime, timedelta, timezone

from app import db
from app.risk import incident_risk

# Kill-chain progression weight per attack family (used for risk scoring).
FAMILY_PROGRESSION = {
    "credential-attack": 0.4,
    "initial-access": 0.2,
    "web-attack": 0.3,
    "network": 0.25,
    "malware": 0.5,
    "phishing": 0.35,
    "privilege": 0.6,
    "exfiltration": 0.8,
    "ransomware": 0.9,
}

MITRE_BY_CATEGORY = {
    "credential-attack": ["T1110", "T1078"],
    "web-attack": ["T1190", "T1189"],
    "network": ["T1046"],
    "malware": ["T1204", "T1059"],
    "phishing": ["T1566"],
    "privilege": ["T1548", "T1078"],
    "exfiltration": ["T1041", "T1048"],
    "ransomware": ["T1486", "T1490"],
    "dos": ["T1498", "T1499"],
    "insider": ["T1078"],
}

RECOMMENDATIONS_BY_CATEGORY = {
    "credential-attack": [
        "Verify the affected accounts for unauthorized access.",
        "Reset passwords and revoke suspicious sessions for affected accounts.",
        "Block the offending source IP at the network boundary.",
        "Enable/enforce MFA on affected accounts.",
    ],
    "web-attack": [
        "Review WAF rules and application logs for the matched request patterns.",
        "Validate input handling on the targeted endpoints.",
        "Block the offending source IP if the pattern is confirmed malicious.",
    ],
    "network": [
        "Review the scanning source and block it if not authorized.",
        "Confirm whether any probed services are exposed unnecessarily.",
    ],
    "malware": [
        "Quarantine the reported file and preserve evidence.",
        "Run an endpoint scan on the affected host.",
        "Check for persistence mechanisms associated with the file.",
    ],
    "phishing": [
        "Warn users about the reported phishing URL and revoke any submitted credentials.",
        "Block the phishing URL/domain at the gateway and via email filtering.",
        "Review mail-flow logs for deliveries of the same campaign.",
        "Run the reported URL through the phishing analyzer for the evidence trail.",
    ],
    "privilege": [
        "Review the privilege change request and its approval trail.",
        "Audit elevated sessions created around the change time.",
    ],
    "exfiltration": [
        "Capture connection evidence for the external destination.",
        "Review data-access logs for sensitive repositories.",
        "Block or rate-limit the destination if confirmed unauthorized.",
        "Verify backup integrity and prepare recovery guidance.",
    ],
    "ransomware": [
        "Contain the affected host (network isolation).",
        "Preserve evidence for analysis.",
        "Verify backups and enable snapshot protection.",
        "Notify incident response immediately.",
    ],
    "dos": [
        "Confirm the traffic baseline and compare with learned normal.",
        "Apply rate limiting / DDoS mitigation at the edge.",
        "Block offending source ranges if volumetric.",
    ],
    "insider": [
        "Review the anomalous user activity with context.",
        "Contact the user to validate the activity before escalation.",
        "Do not label as malicious based on a single anomaly.",
    ],
    "generic": [
        "Review the correlated events for additional context.",
        "Determine whether the activity matches expected behavior.",
    ],
}


def _family_for(category: str) -> str:
    return category if category in FAMILY_PROGRESSION else "generic"


def _progression(categories: list[str]) -> float:
    if not categories:
        return 0.0
    return max(FAMILY_PROGRESSION.get(_family_for(c), 0.0) for c in categories)


class Correlator:
    WINDOW_HOURS = 6
    MAX_OPEN_INCIDENTS = 500

    def _open_incidents(self) -> list[dict]:
        return db.list_incidents(limit=self.MAX_OPEN_INCIDENTS)

    def _find_matching(self, detection: dict, incidents: list[dict]) -> dict | None:
        src = detection.get("source_ip", "")
        user = detection.get("username", "")
        host = detection.get("host", "")
        category = detection.get("category", "generic")
        for inc in incidents:
            if inc["status"] not in ("NEW", "INVESTIGATING", "CONTAINED"):
                continue
            same_key = (
                (src and inc["source_ip"] == src)
                or (user and inc["affected_user"] == user)
                or (host and inc["affected_host"] == host)
            )
            if not same_key:
                continue
            try:
                created = datetime.fromisoformat(inc["created_at"])
            except Exception:
                created = datetime.now(timezone.utc)
            if datetime.now(timezone.utc) - created > timedelta(hours=self.WINDOW_HOURS):
                continue
            # Prefer matching family, otherwise reuse if categories are related.
            if _family_for(inc["category"]) == _family_for(category):
                return inc
            related = {_family_for(c), _family_for(inc["category"])}
            if "exfiltration" in related or "ransomware" in related:
                return inc
        return None

    def correlate(self, detection: dict, event: dict, ti_bonus: float = 0.0,
                  ai_explanation: str = "", risk_score: int = 0) -> dict:
        """Correlate a detection with an open incident or create a new one."""
        incidents = self._open_incidents()
        inc = self._find_matching(detection, incidents)

        category = detection.get("category", "generic")
        severity = detection.get("severity", "medium")
        src = detection.get("source_ip", event.get("source_ip", ""))
        user = detection.get("username", event.get("username", ""))
        host = detection.get("host", event.get("host", ""))
        detection_risk = risk_score or detection.get("risk_score", 0)

        if inc:
            # Append to existing incident.
            event_ids = list(inc.get("event_ids", []))
            if event.get("event_id") and event["event_id"] not in event_ids:
                event_ids.append(event["event_id"])
            timeline = list(inc.get("timeline", []))
            timeline.append({
                "time": event.get("ts"),
                "event_id": event.get("event_id"),
                "type": event.get("event_type"),
                "severity": event.get("severity"),
                "rule": detection.get("rule_name"),
                "description": detection.get("description", ""),
            })
            mitre = list(dict.fromkeys(inc.get("mitre", []) + detection.get("mitre", [])))
            categories = list(dict.fromkeys([inc["category"], category]))
            risk = incident_risk([{"risk_score": detection_risk}],
                                 progression=_progression(categories), ti_bonus=ti_bonus)
            risk = max(risk, int(inc.get("risk_score", 0)))
            severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            if severity_rank.get(severity, 1) > severity_rank.get(inc.get("severity", "medium"), 1):
                severity = severity
            db.update_incident(
                inc["incident_id"],
                event_ids=event_ids,
                timeline=timeline,
                mitre=mitre,
                risk_score=risk,
                severity=severity,
                category=";".join(categories),
                ai_explanation=ai_explanation or inc.get("ai_explanation", ""),
            )
            if event.get("event_id"):
                db.link_event_to_incident(inc["incident_id"], event["event_id"])
            return db.get_incident(inc["incident_id"])

        # Create a new incident.
        title = self._title(detection, src, user, host)
        mitre = list(dict.fromkeys(detection.get("mitre", []) + MITRE_BY_CATEGORY.get(category, [])))
        event_ids = [event["event_id"]] if event.get("event_id") else []
        timeline = [{
            "time": event.get("ts"),
            "event_id": event.get("event_id"),
            "type": event.get("event_type"),
            "severity": event.get("severity"),
            "rule": detection.get("rule_name"),
            "description": detection.get("description", ""),
        }]
        actions = RECOMMENDATIONS_BY_CATEGORY.get(category, RECOMMENDATIONS_BY_CATEGORY["generic"])
        risk = incident_risk([{"risk_score": detection_risk}],
                             progression=_progression([category]), ti_bonus=ti_bonus)
        risk = max(risk, detection_risk)
        inc = db.save_incident({
            "title": title,
            "severity": severity,
            "status": "NEW",
            "risk_score": risk,
            "confidence": detection.get("confidence", 0.0) or 0.5,
            "category": category,
            "affected_host": host,
            "affected_user": user,
            "source_ip": src,
            "dest_ip": detection.get("dest_ip", event.get("dest_ip", "")),
            "timeline": timeline,
            "event_ids": event_ids,
            "evidence": [{"event_id": event.get("event_id"), "type": event.get("event_type"),
                          "time": event.get("ts"), "details": event.get("details", {})}],
            "mitre": mitre,
            "ai_explanation": ai_explanation,
            "detection_rules": [{"rule_id": detection.get("rule_id"), "name": detection.get("rule_name")}],
            "recommended_actions": actions,
        })
        if event.get("event_id"):
            db.link_event_to_incident(inc["incident_id"], event["event_id"])
        return inc

    def _title(self, detection: dict, src: str, user: str, host: str) -> str:
        rule = detection.get("rule_name") or "Suspicious activity"
        scope = src or user or host or "unknown asset"
        return f"{rule} - {scope}"


correlator = Correlator()
