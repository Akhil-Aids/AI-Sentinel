"""SOC report generation from real database data.

Report types:
  * daily   - operator activity summary (alerts, incidents, events, top sources,
              top rules, threat indicators, trend).
  * posture - security posture snapshot (score, open risk, host health).
  * incident- full incident report (timeline, evidence, events, actions).

Every figure is computed from the persisted store; reports never fabricate
values. Period windows default to the current UTC day and are validated.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from app import db
from app.risk import risk_level


def _parse_ts(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _today_range() -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.isoformat(), now.isoformat()


def _resolve_period(period_start: str | None, period_end: str | None) -> tuple[str, str]:
    if not period_start or not period_end:
        return _today_range()
    start = _parse_ts(period_start)
    end = _parse_ts(period_end)
    if not start or not end or end <= start:
        return _today_range()
    return start.isoformat(), end.isoformat()


def _severity_counts(rows: list[dict]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in rows:
        sev = str(r.get("severity", "info"))
        out[sev] = out.get(sev, 0) + 1
    return out


def build_daily_report(period_start: str | None = None, period_end: str | None = None) -> dict:
    start, end = _resolve_period(period_start, period_end)
    period_label = f"{start[:10]} {start[11:19]}Z - {end[:10]} {end[11:19]}Z"

    alerts = db._fetch_all(
        "SELECT severity, status, source FROM alerts WHERE created_at >= ? AND created_at <= ?",
        (start, end),
    )
    incidents = db._fetch_all(
        "SELECT * FROM incidents WHERE created_at >= ? AND created_at <= ?",
        (start, end),
    )
    events = db._fetch_all(
        "SELECT event_type, severity, source_ip, dest_ip, host FROM events WHERE ts >= ? AND ts <= ?",
        (start, end),
    )
    resolved = db._fetch_all(
        "SELECT * FROM incidents WHERE resolved_at >= ? AND resolved_at <= ?",
        (start, end),
    )
    threat_indicators = db._fetch_all(
        "SELECT source, verdict FROM threat_intel WHERE last_seen >= ? AND last_seen <= ?",
        (start, end),
    )

    top_sources = Counter()
    for e in events:
        if e.get("source_ip"):
            top_sources[e["source_ip"]] += 1
    top_hosts = Counter()
    for e in events:
        if e.get("host"):
            top_hosts[e["host"]] += 1
    top_rules = Counter()
    for a in alerts:
        if a.get("source"):
            top_rules[a["source"]] += 1

    alert_by_day: dict[str, int] = defaultdict(int)
    for a in db._fetch_all(
            "SELECT created_at FROM alerts WHERE created_at >= ? AND created_at <= ?", (start, end)):
        day = (a["created_at"] or "")[:10]
        alert_by_day[day] += 1

    security = {
        "score": _security_score(),
    }

    summary = (f"{len(alerts)} alerts, {len(incidents)} incidents, {len(events)} events "
               f"in {period_label}.")
    return {
        "report_type": "daily",
        "period": {"start": start, "end": end, "label": period_label},
        "summary": summary,
        "alerts": {
            "total": len(alerts),
            "by_severity": _severity_counts(alerts),
            "by_status": dict(Counter(a.get("status", "UNKNOWN") for a in alerts)),
            "top_rules": top_rules.most_common(10),
            "trend": [{"date": d, "count": c} for d, c in sorted(alert_by_day.items())],
        },
        "incidents": {
            "created": len(incidents),
            "resolved": len(resolved),
            "by_severity": _severity_counts(incidents),
            "open": len(incidents),
        },
        "events": {
            "total": len(events),
            "by_severity": _severity_counts(events),
            "event_types": dict(Counter(e.get("event_type", "unknown") for e in events).most_common(15)),
            "top_source_ips": top_sources.most_common(10),
            "top_hosts": top_hosts.most_common(10),
        },
        "threat_intel": {
            "indicators": len(threat_indicators),
            "by_source": dict(Counter(t.get("source", "local") for t in threat_indicators)),
        },
        "security_score": security,
    }


def build_posture_report() -> dict:
    servers = db.list_servers()
    incidents = db.list_incidents(limit=200)
    open_incidents = [i for i in incidents if i["status"] not in ("RESOLVED", "FALSE_POSITIVE")]
    alerts = db.list_alerts(limit=200)
    score = _security_score()

    hosts: dict[str, dict] = {}
    for s in servers:
        name = s.get("hostname", "")
        stats = db.list_server_stats(name, limit=1)
        latest = stats[0] if stats else {}
        hosts[name] = {
            "hostname": name,
            "status": s.get("status", "unknown"),
            "cpu": latest.get("cpu", 0),
            "memory": latest.get("memory", 0),
            "disk": latest.get("disk", 0),
            "ip": s.get("ip", ""),
            "os": s.get("os", ""),
        }
    host_risk: dict[str, int] = defaultdict(int)
    for inc in open_incidents:
        h = inc.get("affected_host", "")
        if h:
            host_risk[h] = max(host_risk[h], inc.get("risk_score", 0) or 0)

    recommendations = []
    for inc in open_incidents:
        for action in (inc.get("recommended_actions") or [])[:2]:
            if isinstance(action, dict) and action.get("action"):
                recommendations.append({
                    "incident_id": inc.get("incident_id"),
                    "host": inc.get("affected_host", ""),
                    "action": action.get("action"),
                })

    return {
        "report_type": "posture",
        "assessed_at": datetime.now(timezone.utc).isoformat(),
        "summary": (f"Security score {score['score']}/100 ({score['level'].upper()}), "
                    f"{len(open_incidents)} open incidents, {len(servers)} monitored hosts."),
        "security_score": score,
        "risk": {"level": risk_level(_overall_risk(open_incidents))},
        "open_incidents": {
            "count": len(open_incidents),
            "by_severity": _severity_counts(open_incidents),
        },
        "alerts": {
            "total": len(alerts),
            "open": sum(1 for a in alerts if a.get("status") == "NEW"),
            "by_severity": _severity_counts(alerts),
        },
        "hosts": {
            "total": len(servers),
            "online": sum(1 for h in hosts.values() if h["status"] == "online"),
            "critical": sum(1 for h in hosts.values() if h["cpu"] >= 90 or h["disk"] >= 92),
            "at_risk": [{"hostname": k, "risk_score": v} for k, v in
                        sorted(host_risk.items(), key=lambda kv: -kv[1])[:10]],
        },
        "recommendations": recommendations[:20],
    }


def build_incident_report(incident_id: str) -> dict:
    inc = db.get_incident(incident_id)
    if not inc:
        raise KeyError(incident_id)
    events = []
    for eid in (inc.get("event_ids") or []):
        ev = db.get_event_by_id(eid)
        if ev:
            events.append(ev)
    return {
        "report_type": "incident",
        "incident": {k: inc[k] for k in inc if k not in ("event_ids",)},
        "events": events,
        "summary": f"Incident {inc.get('incident_id')} - {inc.get('title')} ({inc.get('severity', '').upper()})",
    }


def _security_score(open_incidents: list[dict] | None = None) -> dict:
    """Deterministic score: 100 minus weighted risk of open items."""
    incidents = open_incidents
    if incidents is None:
        incidents = [i for i in db.list_incidents(limit=200)
                     if i["status"] not in ("RESOLVED", "FALSE_POSITIVE")]
    alerts = db.list_alerts(limit=200)
    weights = {"low": 10, "medium": 25, "high": 45, "critical": 70}
    total = 0.0
    for inc in incidents:
        total += (inc.get("risk_score", 0) / 100.0) * 1.0
    for al in alerts:
        total += weights.get(al.get("severity", "low"), 10) / 100.0 * 0.5
    score = max(0, int(100 - total * 15))
    level = "good" if score >= 85 else ("fair" if score >= 60 else "poor")
    return {"score": score, "level": level}


def _overall_risk(open_incidents: list[dict]) -> int:
    if not open_incidents:
        return 0
    max_risk = max(i.get("risk_score", 0) for i in open_incidents)
    return min(100, max_risk + min(10, len(open_incidents) * 2))