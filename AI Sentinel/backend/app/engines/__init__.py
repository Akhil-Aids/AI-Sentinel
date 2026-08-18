"""Detection engine package.

Combines the configurable rule engine with structural detectors (web attacks,
suspicious files, ML anomaly) into a single `DetectionEngine` used by the
event pipeline.
"""
from app.engines.rules import rule_engine, seed_default_rules, is_rule_enabled
from app.engines.webattacks import analyze_web_request


class DetectionEngine:
    def __init__(self, ml=None):
        self.ml = ml

    def analyze(self, ev: dict) -> dict:
        """Analyze one normalized event.

        Returns:
            {
                "detections": [detection...],   # rule-engine detections
                "ml_anomaly": {..} or None,
                "risk_add": float,               # additional risk contribution
            }
        """
        detections = []

        # Structural analysis for web requests.
        if ev.get("event_type") in {"web.request", "app.request"}:
            detections.extend(self._web_attack_detections(ev))

        # Rule-engine detections.
        detections.extend(rule_engine.evaluate(ev))

        # ML anomaly scoring.
        ml_anomaly = None
        if self.ml is not None and self.ml.enabled():
            ml_anomaly = self.ml.score_event(ev)

        return {"detections": detections, "ml_anomaly": ml_anomaly}

    def _web_attack_detections(self, ev: dict) -> list[dict]:
        details = ev.get("details", {}) or {}
        matches = analyze_web_request(
            details.get("method", ""),
            details.get("path", ev.get("target", "")),
            details.get("query", ""),
            details.get("body", ""),
            details.get("headers", ""),
        )
        kind_map = {
            "sql_injection": {
                "rule_id": "sql_injection",
                "rule_name": "SQL injection pattern in request",
                "category": "web-attack",
                "severity": "high",
                "mitre": ["T1190", "T1189"],
            },
            "xss": {
                "rule_id": "xss",
                "rule_name": "Cross-site scripting pattern in request",
                "category": "web-attack",
                "severity": "medium",
                "mitre": ["T1059.007", "T1189"],
            },
            "command_injection": {
                "rule_id": "command_injection",
                "rule_name": "Command injection pattern in request",
                "category": "web-attack",
                "severity": "high",
                "mitre": ["T1059", "T1190"],
            },
            "path_traversal": {
                "rule_id": "path_traversal",
                "rule_name": "Path traversal pattern in request",
                "category": "web-attack",
                "severity": "medium",
                "mitre": ["T1083", "T1005"],
            },
        }
        out = []
        for m in matches:
            meta = kind_map.get(m["kind"])
            if not meta:
                continue
            # Structural detectors respect the persisted enabled flag so an
            # operator disabling the rule also disables its structural path.
            if not is_rule_enabled(meta["rule_id"]):
                continue
            out.append({
                "event_id": ev.get("event_id"),
                "rule_id": meta["rule_id"],
                "rule_name": meta["rule_name"],
                "description": f"Web request matched pattern '{m['pattern']}'.",
                "category": meta["category"],
                "severity": meta["severity"],
                "mitre": meta["mitre"],
                "source_ip": ev.get("source_ip", ""),
                "dest_ip": ev.get("dest_ip", ""),
                "host": ev.get("host", ""),
                "username": ev.get("username", ""),
                "matched_pattern": m["pattern"],
            })
        return out


def build_detection_engine(ml=None) -> DetectionEngine:
    return DetectionEngine(ml=ml)
