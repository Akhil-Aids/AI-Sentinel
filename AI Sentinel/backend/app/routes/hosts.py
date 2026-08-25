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
    """Single host detail with history and baseline."""
    server = db.get_server(hostname)
    if not server:
        raise HTTPException(status_code=404, detail="Host not found")
    stats = db.list_server_stats(hostname, limit=120)
    return {**server, "stats": stats}
