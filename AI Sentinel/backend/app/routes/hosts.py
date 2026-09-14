"""Hosts/servers route — real telemetry from the collector."""
from fastapi import APIRouter, Depends, HTTPException

from app import db
from app.core.deps import current_user

router = APIRouter()


@router.get("/")
def list_hosts(_payload: dict = Depends(current_user)) -> dict:
    """All monitored hosts with real telemetry."""
    servers = db.list_servers()
    items = []
    for s in servers:
        hostname = s.get("hostname", "")
        stats = db.list_server_stats(hostname, limit=1)
        latest = stats[0] if stats else {}
        items.append({
            "hostname": hostname,
            "ip": s.get("ip", ""),
            "os": s.get("os", ""),
            "platform": s.get("platform", ""),
            "status": s.get("status", "unknown"),
            "environment": s.get("environment", ""),
            "agent_id": s.get("agent_id", ""),
            "last_seen_at": s.get("last_seen_at", s.get("last_heartbeat_at", "")),
            "cpu": latest.get("cpu", 0),
            "memory": latest.get("memory", 0),
            "disk": latest.get("disk", 0),
            "processes": latest.get("process_count", 0),
            "network_mbps": latest.get("network_mbps", 0),
        })
    return {"items": items, "total": len(items)}


@router.get("/{hostname}")
def get_host(hostname: str, _payload: dict = Depends(current_user)) -> dict:
    """Single host investigation view: telemetry plus related events, alerts,
    incidents and an absolute risk score computed from live open findings."""
    server = db.get_server(hostname)
    if not server:
        raise HTTPException(status_code=404, detail="Host not found")
    stats = db.list_server_stats(hostname, limit=240)
    events = db.list_events(limit=50, host=hostname)

    # Alerts that reference events originating from this host.
    alerts = []
    for al in db.list_alerts(limit=200):
        ids = al.get("event_ids") or []
        found = False
        for eid in ids[:50]:
            ev = db.get_event_by_id(eid)
            if ev and ev.get("host") == hostname:
                found = True
                break
        if found:
            alerts.append(al)

    # Incidents affecting this host.
    incidents = [i for i in db.list_incidents(limit=200)
                 if i.get("affected_host") == hostname]

    # Host risk driven by its own open alerts/incidents (not environment-wide).
    weights = {"low": 10, "medium": 25, "high": 45, "critical": 70}
    risk = 0
    for al in alerts:
        if al.get("status") not in ("RESOLVED", "FALSE_POSITIVE"):
            risk += weights.get(al.get("severity", "low"), 10)
    open_inc = [i for i in incidents if i["status"] not in ("RESOLVED", "FALSE_POSITIVE")]
    risk = min(100, risk + sum((i.get("risk_score", 0) or 0) // 10 for i in open_inc))

    network = db._fetch_all(
        "SELECT id, ts, event_type, source_ip, dest_ip, port, protocol, username, severity "
        "FROM events WHERE host = ? AND event_type IN ('net.connection','net.connection_failed') "
        "ORDER BY ts DESC LIMIT 30", (hostname,))

    return {
        **server,
        "stats": stats,
        "events": events,
        "alerts": alerts,
        "incidents": incidents,
        "network": network,
        "risk_score": risk,
        "risk_band": "critical" if risk >= 80 else ("high" if risk >= 60 else ("elevated" if risk >= 30 else "normal")),
    }
