"""Risk scoring engine.

Produces a standardized 0-100 risk score and level:
  0-30 LOW, 31-60 MEDIUM, 61-80 HIGH, 81-100 CRITICAL.

Risk considers event severity, confidence, asset criticality, event count,
attack progression, and threat-intelligence weight. It is a deterministic,
auditable function (no random component).
"""
import math

SEVERITY_WEIGHT = {"info": 0, "low": 10, "medium": 25, "high": 45, "critical": 70}
ASSET_CRITICALITY = {"default": 10, "high": 30, "critical": 45, "low": 0}

LEVELS = [
    (81, "critical"),
    (61, "high"),
    (31, "medium"),
    (0, "low"),
]


def risk_level(score: int) -> str:
    for threshold, level in LEVELS:
        if score >= threshold:
            return level
    return "low"


def combine_risks(scores: list[float]) -> float:
    """Combine multiple 0-100 risk scores (noisy-OR style, bounded)."""
    if not scores:
        return 0.0
    score = 1.0
    for s in scores:
        score *= 1.0 - min(max(float(s), 0.0), 100.0) / 100.0
    return (1.0 - score) * 100.0


def event_risk(event: dict, asset_criticality: str = "default", ti_bonus: float = 0.0) -> int:
    """Risk of a single event (0-100)."""
    sev = SEVERITY_WEIGHT.get(str(event.get("severity", "info")).lower(), 0)
    conf = min(max(float(event.get("confidence", 0.0)), 0.0), 1.0)
    asset = ASSET_CRITICALITY.get(asset_criticality, ASSET_CRITICALITY["default"])

    base = 0.25 * sev + 0.30 * (conf * 100) + 0.20 * asset
    # Small multiplicative bumps for high severity / confidence.
    if sev >= 45:
        base *= 1.10
    if conf >= 0.85:
        base *= 1.10
    base += ti_bonus
    return int(min(100, max(0, round(base))))


def incident_risk(events: list[dict], progression: float = 0.0, ti_bonus: float = 0.0) -> int:
    """Risk of a correlated incident.

    events: the correlated events.
    progression: fraction of the attack chain observed (0-1).
    ti_bonus: threat-intelligence derived weight (0-100).
    """
    if not events:
        return 0
    event_scores = [event_risk(e) for e in events]
    base = combine_risks(event_scores)
    count_factor = min(1.0, math.log10(len(events) + 1) / 2.0)  # more events => more risk
    score = base * (0.7 + 0.3 * count_factor)
    score = score * (0.75 + 0.25 * min(max(progression, 0.0), 1.0))
    score += min(ti_bonus, 25.0)
    return int(min(100, max(0, round(score))))
