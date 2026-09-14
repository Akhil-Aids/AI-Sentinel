"""Security posture engine.

The score is always derived from the real, queryable state of the platform:
live event flow, rule health, SLA state, evidence coverage, open work and MFA
adoption. There is no magic factor — every point is an explained delta and a
component the UI can drill into. Down states always pull the score down.
"""
from datetime import datetime, timedelta, timezone

from app import db
from app.services import mitre_center, sla as sla_service

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def compute() -> dict:
    factors: list[dict] = []
    deltas: list[dict] = []
    score = 100

    def _apply(delta_child: dict, weight: float, weight_max: float) -> None:
        nonlocal score
        factor = delta_child.pop("factor")
        capped = max(-weight_max, min(weight_max, weight))
        score = max(0, min(100, score + capped))
        deltas.append({"factor": factor, "delta": round(capped, 1),
                       "detail": delta_child.get("detail", "")})
        factors.append({"factor": factor, "factor_delta": round(capped, 1)} | delta_child)

    # 1. Live event flow (40% of penalty headroom, bonuses for healthy flow).
    now = datetime.now(timezone.utc)
    hour_ago = (now - timedelta(hours=1)).isoformat()
    events_1h = db.count_events(since=hour_ago)
    if events_1h == 0:
        flow_penalty = 40.0
    elif events_1h < 5:
        flow_penalty = 15.0
    else:
        flow_penalty = 0.0
    _apply({"factor": "event_flow", "value": events_1h,
            "msg": f"{events_1h} events in the last hour",
            "detail": "No telemetry in the last hour is the single worst signal — with no data there is no coverage."
                      if flow_penalty >= 40 else
                      "Thin telemetry volume weakens detection fidelity."},
           -flow_penalty, 40)

    # 2. Detection rule health (30%).
    rules = db.list_rules()
    enabled = [r for r in rules if r.get("enabled")]
    disabled = [r for r in rules if not r.get("enabled")]
    stale = [r for r in enabled if _stale_days(r.get("updated_at", "")) > 90]
    if not enabled:
        _apply({"factor": "rule_health", "value": 0, "msg": "No detection rules are enabled",
                "detail": "A SOC with zero active rules cannot claim coverage."}, -40, 30)
    else:
        penalty = min(40, 40 * (len(disabled) / max(1, len(rules))))
        _apply({"factor": "rule_health", "value": len(enabled), "enabled": len(enabled),
                "disabled": len(disabled), "stale": len(stale),
                "msg": f"{len(enabled)} enabled / {len(disabled)} disabled rules",
                "detail": "High disabled-rule ratio or stale enabled rules weaken coverage."},
               -penalty, 30)

    # 3. Incidents + SLA performance (20%).
    incidents = db.list_incidents(limit=1000)
    sla_rows = sla_service.sla_for_incidents(incidents)
    breached = [i for i in sla_rows if (i.get("sla") or {}).get("state") == "BREACHED"]
    incident_penalty = min(25, 25 * len(breached) / max(1, len(sla_rows))) if sla_rows else 0
    _apply({"factor": "incident_sla", "value": len(sla_rows), "breached": len(breached),
            "msg": f"{len(breached)}/{len(sla_rows)} incidents breach SLA",
            "detail": "SLA breaches erode incident-response maturity."}, -incident_penalty, 20)

    # 4. Evidence coverage on incidents (10%).
    with_evidence = sum(1 for inc in incidents if db.list_evidence(incident_id=inc["incident_id"]))
    ev_ratio = with_evidence / max(1, len(incidents))
    _apply({"factor": "evidence_coverage", "value": round(ev_ratio * 100, 1),
            "msg": f"{with_evidence}/{len(incidents)} incidents carry evidence",
            "detail": "Low evidence coverage undermines forensic integrity."},
           -(1 - ev_ratio) * 10, 10)

    # 5. Open work: alerts, tasks, cases (10%).
    open_alerts = len(db.list_alerts(status="OPEN"))
    open_tasks = len(db.list_tasks(status="TODO"))
    open_cases = len(db.list_cases(status="OPEN"))
    work_penalty = min(20, 0.05 * open_alerts + 0.05 * open_tasks + 0.05 * open_cases)
    _apply({"factor": "open_work", "value": {"alerts": open_alerts, "tasks": open_tasks, "cases": open_cases},
            "msg": f"{open_alerts} open alerts / {open_tasks} open tasks / {open_cases} open cases",
            "detail": "Unprocessed work erodes detection-to-respond cycles."}, -work_penalty, 10)

    # 6. MFA adoption (bonus, never a penalty).
    users = db.list_users()
    mfa_enabled = sum(1 for u in users if u.get("mfa_enabled"))
    if users and mfa_enabled:
        bonus = 5.0 * (mfa_enabled / len(users))
        _apply({"factor": "mfa_adoption", "value": round(100 * mfa_enabled / len(users), 1),
                "msg": f"{mfa_enabled}/{len(users)} users with MFA",
                "detail": "Higher MFA adoption raises authentication assurance."}, bonus, 5)

    # 7. API key hygiene (bonus).
    unused_keys = len([k for k in db.list_api_keys() if not k.get("last_used_at")])
    if not unused_keys:
        _apply({"factor": "key_hygiene", "value": "all_used", "msg": "All API keys recently used",
                "detail": "No idle API keys."}, 0, 5)

    status = "CRITICAL" if score < 40 else ("POOR" if score < 60 else
                                            ("FAIR" if score < 80 else "GOOD"))
    return {
        "score": round(score, 1),
        "status": status,
        "computed_at": now.isoformat(),
        "factors": factors,
        "deltas": deltas,
        "coverage": mitre_center.coverage()["coverage"],
    }


def _stale_days(ts: str) -> int:
    if not ts:
        return 999
    try:
        parsed = datetime.fromisoformat(ts)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - parsed).days)
    except Exception:
        return 999