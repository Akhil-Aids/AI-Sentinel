"""Grounded security assistant.

Answers questions strictly from live, real telemetry stored in the database.
No external LLM is called and no data is fabricated. Every answer cites the
actual values it is based on.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app import db
from app.core.deps import current_user
from app.risk import risk_level

router = APIRouter()


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=1000)


def _live_context() -> dict:
    incidents = db.list_incidents(limit=50)
    alerts = db.list_alerts(limit=100)
    servers = db.list_servers()
    now = datetime.now(timezone.utc)
    hour_ago = (now - timedelta(hours=1)).isoformat()
    events_hour = db.count_events(since=hour_ago)
    open_incidents = [i for i in incidents if i["status"] not in ("RESOLVED", "FALSE_POSITIVE")]

    if open_incidents:
        max_risk = max(i.get("risk_score", 0) for i in open_incidents)
        overall = min(100, max_risk + min(10, len(open_incidents) * 2))
    else:
        overall = 0

    return {
        "risk": {"score": overall, "level": risk_level(overall)},
        "incidents": incidents,
        "open_incidents": open_incidents,
        "alerts": alerts,
        "servers": servers,
        "events_last_hour": events_hour,
        "critical_alerts": sum(1 for a in alerts if a.get("severity") == "critical"),
        "high_alerts": sum(1 for a in alerts if a.get("severity") == "high"),
    }


def _answer(question: str, ctx: dict) -> str:
    q = question.lower()
    risk = ctx["risk"]
    servers = ctx["servers"]
    incidents = ctx["open_incidents"]

    if any(w in q for w in ["risk", "danger", "threat level", "how safe"]):
        parts = [f"Current environment risk is {risk['level'].upper()} ({risk['score']}/100)."]
        if incidents:
            top = max(incidents, key=lambda i: i.get("risk_score", 0))
            parts.append(f"There are {len(incidents)} open incident(s); the highest-risk is '{top['title']}' "
                         f"({top.get('severity', 'unknown')}, score {top.get('risk_score', 0)}).")
            parts.append(f"Evidence: incident {top.get('incident_id', 'unknown')} on "
                         f"{top.get('affected_host') or 'unknown host'}, user "
                         f"{top.get('affected_user') or 'unknown'}, category {top.get('category', 'generic')}.")
        else:
            parts.append("There are no open incidents.")
        return " ".join(parts)

    if any(w in q for w in ["incident", "attack", "breach", "compromis", "malware", "ransomware"]):
        if not incidents:
            return ("There are no open incidents. No active attack is being reported by the detection engines "
                    "based on current telemetry.")
        lines = [f"{len(incidents)} open incident(s):"]
        for i in incidents[:5]:
            lines.append(f"  - [{i.get('severity', '?').upper()}] {i['title']} (risk {i.get('risk_score', 0)}) "
                         f"- {i.get('category', 'generic')} - {i.get('status', '')} - incident {i.get('incident_id', '?')}")
        lines.append("Each incident ID is evidence-linked; open it for the full timeline and event evidence.")
        return "\n".join(lines)

    if any(w in q for w in ["phish", "url", "malicious link", "scam"]):
        scans = db.list_phishing(limit=25)
        if not scans:
            return "No phishing scans have been run through the analyzer yet. Submit a URL on the Phishing page."
        malicious = [s for s in scans if s.get("verdict") == "MALICIOUS"]
        suspicious = [s for s in scans if s.get("verdict") == "SUSPICIOUS"]
        lines = [f"Last {len(scans)} phishing scans: {len(malicious)} malicious, {len(suspicious)} suspicious."]
        for s in malicious[:3]:
            lines.append(f"  - MALICIOUS {s['url']} (risk {s.get('risk_score', 0)}) - {', '.join((s.get('reasons') or [])[:2])}")
        if not malicious:
            lines.append("No MALICIOUS verdicts in the recent scan history.")
        return "\n".join(lines)

    if any(w in q for w in ["alert", "notification"]):
        if not ctx["alerts"]:
            return "There are no stored alerts at the moment."
        crit = ctx["critical_alerts"]
        high = ctx["high_alerts"]
        newest = ctx["alerts"][:3]
        lines = [f"There are {len(ctx['alerts'])} stored alerts: {crit} critical, {high} high."]
        for a in newest:
            lines.append(f"  - [{a.get('severity', '?').upper()}] {a.get('title', '?')} (alert {a.get('alert_id', '?')})")
        return "\n".join(lines)

    if any(w in q for w in ["server", "host", "machine", "system health", "cpu", "memory", "disk"]):
        if not servers:
            return "No server telemetry has been collected yet. The collector will begin reporting shortly."
        lines = ["Current server telemetry:"]
        for s in servers[:10]:
            lines.append(f"  - {s['hostname']}: CPU {s.get('cpu', 0)}%, memory {s.get('memory', 0)}%, "
                         f"disk {s.get('disk', 0)}%, processes {s.get('processes', 0)}")
        return "\n".join(lines)

    if any(w in q for w in ["events", "traffic", "throughput", "network activity"]):
        return (f"{ctx['events_last_hour']} security events were ingested in the last hour. "
                f"{ctx['critical_alerts']} critical and {ctx['high_alerts']} high alerts are stored. "
                "See the Live Events feed for the raw stream.")

    if any(w in q for w in ["what should i do", "respond", "action", "next step", "recommend"]):
        if not incidents:
            return "No open incidents, so no urgent action is required. Keep monitoring."
        lines = ["Based on the open incidents, recommended actions:"]
        for i in incidents[:3]:
            actions = i.get("recommended_actions", [])
            if actions:
                lines.append(f"  - {i['title']}: {actions[0]}")
        lines.append("Open each incident for the full evidence timeline and recommended response.")
        return "\n".join(lines)

    if any(w in q for w in ["mitre", "kill chain", "tactic"]):
        tactics = set()
        for i in incidents:
            for m in i.get("mitre", []):
                tactics.add(m)
        if not tactics:
            return "No MITRE ATT&CK techniques are currently associated with open incidents."
        return "MITRE techniques associated with open incidents: " + ", ".join(sorted(tactics)) + "."

    if any(w in q for w in ["hello", "hi ", "hey", "help", "what can you"]):
        return ("I answer grounded questions using live telemetry: risk level, incidents, alerts, "
                "server health, event volume, MITRE techniques, and recommended actions.")

    return ("I can answer questions about: risk level, open incidents/attacks, alerts, server health, "
            "recent events/traffic, MITRE techniques, and recommended response actions.")


@router.post("/")
def chat(payload: ChatRequest, _user: dict = Depends(current_user)) -> dict:
    ctx = _live_context()
    answer = _answer(payload.message, ctx)
    return {"question": payload.message, "answer": answer, "source": "live-telemetry"}
