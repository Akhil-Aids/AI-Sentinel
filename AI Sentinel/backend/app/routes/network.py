"""Network traffic route backed by real server_stats time series + net events.

All data is derived from real OS observations. `requests_per_sec` is no longer
reported (it was fabricated as connections/interval); the honest rate metric is
`connections_delta` (change in active connections between samples).
"""
import statistics
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from app import db
from app.core.deps import current_user

router = APIRouter()


@router.get("/traffic")
def traffic(_payload: dict = Depends(current_user)) -> dict:
    servers = db.list_servers()
    if not servers:
        return {"series": [], "unit": "Mbps", "current": 0, "hosts": []}

    series: dict[str, list[float]] = {}
    hosts = []
    for s in servers:
        hostname = s["hostname"]
        stats = db.list_server_stats(hostname, limit=30)
        if not stats:
            continue
        stats.reverse()  # chronological
        series[hostname] = [round(st["network_mbps"] or 0, 2) for st in stats]
        hosts.append(hostname)

    if not series:
        return {"series": [], "unit": "Mbps", "current": 0, "hosts": []}

    # Aggregate across hosts (sum of real throughput, not an average).
    length = max(len(v) for v in series.values())
    agg = []
    for i in range(length):
        values = [v[i] for v in series.values() if i < len(v)]
        agg.append(round(sum(values), 2))

    return {"series": agg, "unit": "Mbps", "current": agg[-1] if agg else 0, "hosts": hosts}


@router.get("/connections")
def connections(_payload: dict = Depends(current_user)) -> dict:
    """Recent real network connection events."""
    items = db.list_events(limit=100, event_type="net.connection")
    return {"items": items}


@router.get("/servers")
def servers(_payload: dict = Depends(current_user)) -> dict:
    items = db.list_servers()
    out = []
    for s in items:
        stats = db.list_server_stats(s["hostname"], limit=60)
        stats.reverse()
        out.append({**s, "history": stats, "baseline": _baseline(s["hostname"])})
    return {"items": out}


@router.get("/top")
def top(_payload: dict = Depends(current_user)) -> dict:
    """Top sources, destinations, and ports from real net.connection events."""
    return _top_aggregates()


def _top_aggregates(minutes: int = 60, limit: int = 10) -> dict:
    from datetime import timedelta
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    rows = db.net_connection_columns(since=since)
    sources: dict[str, int] = {}
    destinations: dict[str, int] = {}
    ports: dict[int, int] = {}
    for r in rows:
        src = r.get("source_ip", "")
        dst = r.get("dest_ip", "")
        port = r.get("port", 0)
        if src:
            sources[src] = sources.get(src, 0) + 1
        if dst:
            destinations[dst] = destinations.get(dst, 0) + 1
        if port:
            ports[port] = ports.get(port, 0) + 1
    return {
        "window_minutes": minutes,
        "sources": [{"ip": k, "connections": v} for k, v in sorted(sources.items(), key=lambda kv: -kv[1])[:limit]],
        "destinations": [{"ip": k, "connections": v} for k, v in sorted(destinations.items(), key=lambda kv: -kv[1])[:limit]],
        "ports": [{"port": k, "connections": v} for k, v in sorted(ports.items(), key=lambda kv: -kv[1])[:limit]],
    }


def _baseline(hostname: str) -> dict:
    """Per-host baseline (mean/std) with a deviation flag for current values.

    Deviation is flagged when the latest sample is >= 2 standard deviations
    from the historical mean for cpu/memory/disk/connections.
    """
    stats = db.list_server_stats(hostname, limit=120)
    if len(stats) < 3:
        return {"samples": len(stats), "deviations": []}
    agg: dict[str, list[float]] = {}
    for key in ("cpu", "memory", "disk", "connections"):
        agg[key] = [float(st.get(key) or 0) for st in stats]
    latest = stats[0]
    deviations = []
    for key, values in agg.items():
        mean = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        if std == 0:
            continue
        z = (float(latest.get(key) or 0) - mean) / std
        if abs(z) >= 2.0:
            deviations.append({
                "metric": key, "current": round(float(latest.get(key) or 0), 1),
                "baseline_mean": round(mean, 1), "baseline_std": round(std, 1),
                "z_score": round(z, 2),
            })
    return {
        "samples": len(stats),
        "mean": {k: round(statistics.mean(v), 1) for k, v in agg.items()},
        "deviations": deviations,
    }
