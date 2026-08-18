"""Dashboard overview route: aggregates real telemetry into a SOC overview."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends

from app import db
from app.core.deps import current_user
from app.pipeline import pipeline
from app.risk import risk_level
from app.ml.anomaly import anomaly_detector

router = APIRouter()

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
INCIDENT_WEIGHTS = {"low": 10, "medium": 25, "high": 45, "critical": 70}


def _security_score(open_incidents: list[dict], alerts: list[dict]) -> dict:
    """Security score: 100 minus accumulated weighted risk of open items."""
    total = 0.0
    for inc in open_incidents:
        total += (inc.get("risk_score", 0) / 100.0) * 1.0
    for al in alerts:
        sev = al.get("severity", "low")
        total += INCIDENT_WEIGHTS.get(sev, 10) / 100.0 * 0.5
    score = max(0, int(100 - total * 15))
    level = "good" if score >= 85 else ("fair" if score >= 60 else "poor")
    return {"score": score, "level": level}


def _attack_categories(incidents: list[dict]) -> dict:
    cats: dict[str, int] = {}
    for inc in incidents:
        for c in str(inc.get("category", "generic")).split(";"):
            cats[c.strip()] = cats.get(c.strip(), 0) + 1
    return dict(sorted(cats.items(), key=lambda kv: -kv[1]))


def _risk_trend(incidents: list[dict]) -> list[dict]:
    """Highest open-incident risk per day for the last 7 days."""
    from collections import defaultdict
    per_day: dict[str, int] = defaultdict(int)
    for inc in incidents:
        try:
            day = inc["created_at"][:10]
        except Exception:
            continue
        per_day[day] = max(per_day[day], inc.get("risk_score", 0) or 0)
    today = datetime.now(timezone.utc).date()
    out = []
    for i in range(6, -1, -1):
        day = (today - timedelta(days=i)).isoformat()
        out.append({"date": day, "max_risk": per_day.get(day, 0)})
    return out


def _top_entities(incidents: list[dict]) -> dict:
    """Highest-risk affected hosts and users from open incidents."""
    hosts: dict[str, int] = {}
    users: dict[str, int] = {}
    for inc in incidents:
        host = inc.get("affected_host", "")
        user = inc.get("affected_user", "")
        risk = inc.get("risk_score", 0) or 0
        if host:
            hosts[host] = max(hosts.get(host, 0), risk)
        if user:
            users[user] = max(users.get(user, 0), risk)
    top_hosts = [{"asset": k, "max_risk": v} for k, v in
                 sorted(hosts.items(), key=lambda kv: -kv[1])[:5]]
    top_users = [{"user": k, "max_risk": v} for k, v in
                 sorted(users.items(), key=lambda kv: -kv[1])[:5]]
    return {"hosts": top_hosts, "users": top_users}


@router.get("/overview")
def overview(_payload: dict = Depends(current_user)) -> dict:
    servers = db.list_servers()
    now = datetime.now(timezone.utc)
    day_ago = (now - timedelta(days=1)).isoformat()
    hour_ago = (now - timedelta(hours=1)).isoformat()

    incidents = db.list_incidents(limit=100)
    open_incidents = [i for i in incidents if i["status"] not in ("RESOLVED", "FALSE_POSITIVE")]
    alerts = db.list_alerts(limit=200)

    sev_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for al in alerts:
        sev_counts[al.get("severity", "info")] = sev_counts.get(al.get("severity", "info"), 0) + 1

    events_today = db.count_events(since=day_ago)
    events_hour = db.count_events(since=hour_ago)
    total_events = db.count_events()

    # Distinguish "no threats" from "no data": if no telemetry has ever been
    # received, the dashboard must say NO_DATA rather than implying safety.
    if total_events == 0:
        data_status = "NO_DATA"
    elif events_today == 0:
        data_status = "NO_EVENTS_TODAY"
    else:
        data_status = "OK"

    # Overall environment risk: max open incident risk, biased by open count.
    if open_incidents:
        max_risk = max(i.get("risk_score", 0) for i in open_incidents)
        overall = min(100, max_risk + min(10, len(open_incidents) * 2))
    else:
        overall = 0
    # Floor from high-severity alerts with no incident yet.
    critical_new = sev_counts["critical"] + sev_counts["high"]
    if overall < 30 and critical_new > 0:
        overall = min(40, critical_new * 15)

    return {
        "servers": {
            "total": len(servers),
            "online": sum(1 for s in servers if s.get("status") == "online"),
            "critical": sum(1 for s in servers if (s.get("cpu", 0) >= 90 or s.get("disk", 0) >= 92)),
            "healthy": sum(1 for s in servers if s.get("status") == "online" and s.get("cpu", 0) < 90 and s.get("disk", 0) < 92),
        },
        "incidents": {
            "total": len(incidents),
            "open": len(open_incidents),
            "by_severity": {
                "critical": sum(1 for i in incidents if i.get("severity") == "critical"),
                "high": sum(1 for i in incidents if i.get("severity") == "high"),
                "medium": sum(1 for i in incidents if i.get("severity") == "medium"),
                "low": sum(1 for i in incidents if i.get("severity") == "low"),
            },
        },
        "alerts": {
            "total": len(alerts),
            "critical": sev_counts["critical"],
            "high": sev_counts["high"],
            "medium": sev_counts["medium"],
            "low": sev_counts["low"],
            "open": sum(1 for a in alerts if a.get("status") == "NEW"),
        },
        "events": {
            "today": events_today,
            "last_hour": events_hour,
            "eps": pipeline.stats().get("eps", 0),
            "queue_depth": pipeline.stats().get("queue_depth", 0),
        },
        "risk": {"score": overall, "level": risk_level(overall)},
        "security_score": _security_score(open_incidents, alerts),
        "attack_categories": _attack_categories(incidents),
        "risk_trend": _risk_trend(incidents),
        "top_entities": _top_entities(incidents),
        "data_status": data_status,
        "ml": anomaly_detector.status(),
        "pipeline": pipeline.stats(),
    }
