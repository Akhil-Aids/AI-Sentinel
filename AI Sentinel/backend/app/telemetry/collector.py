"""Background telemetry collector.

Periodically samples real OS metrics (CPU/memory/disk/processes/network/files)
and feeds them into the event pipeline as canonical events. Also maintains the
`servers` registry and `server_stats` time series used by the dashboard.
"""
import asyncio
import time
import uuid
from datetime import datetime, timezone

from app import db
from app.core.config import settings
from app.pipeline import pipeline
from app.telemetry.system_monitor import get_file_monitor, get_system_monitor, hostname

METRICS_INTERVAL = settings.METRICS_INTERVAL
FILE_INTERVAL = settings.FILE_INTERVAL

AGENT_ID_PREFIX = "collector"


def agent_id() -> str:
    return f"{AGENT_ID_PREFIX}-{hostname()}"


async def run_collector_loop(once: bool = False) -> None:
    """Run the collector forever (or once when `once=True` for tests/scripts)."""
    monitor = get_system_monitor()
    file_monitor = get_file_monitor()
    last_file_check = 0.0

    while True:
        try:
            await asyncio.to_thread(collect_cycle, monitor, file_monitor, last_file_check)
        except Exception as exc:
            db.log_audit(actor="collector", action="collector.cycle", result="FAILED",
                         detail={"error": str(exc)})

        if once:
            return
        await asyncio.sleep(METRICS_INTERVAL)
        last_file_check = time.monotonic()


def collect_cycle(monitor, file_monitor, last_file_check: float) -> None:
    """One collection pass. All events are real OS observations."""
    host = hostname()
    now = datetime.now(timezone.utc).isoformat()
    environment = settings.ENVIRONMENT
    ag = agent_id()

    sys_snap = monitor.system_snapshot()
    disk_snap = monitor.disk_snapshot()
    net_snap = monitor.network_snapshot()
    top_procs = monitor.top_processes()

    # ------------------------------------------------------------------ #
    # 1. Server metrics event (used for ML samples and dashboard history).
    #    All fields are real observations; nothing is fabricated.
    # ------------------------------------------------------------------ #
    details = {
        "throughput_mbps": net_snap["throughput_mbps"],
        "connections_delta": net_snap["connection_count_delta"],
        "suspicious_ports": net_snap["suspicious_ports"],
        "active_connections": net_snap["active_connections"],
        "cpu_percent": sys_snap["cpu_percent"],
        "memory_percent": sys_snap["memory_percent"],
        "disk_percent": disk_snap["disk_percent"],
        "process_count": sys_snap["process_count"],
        "uptime_seconds": sys_snap["uptime_seconds"],
        "top_processes": top_procs,
        "load": sys_snap["load"],
    }
    pipeline.ingest({
        "event_id": f"telemetry_{uuid.uuid4().hex[:12]}",
        "ts": now,
        "source": "collector",
        "source_type": "collector",
        "host": host,
        "environment": environment,
        "asset_id": ag,
        "event_type": "telemetry.snapshot",
        "category": "system",
        "severity": "info",
        "details": details,
    }, source="collector")

    # ------------------------------------------------------------------ #
    # 2. Update server registry + stats history + agent heartbeat.
    # ------------------------------------------------------------------ #
    db.upsert_server(host, {
        "ip": ",".join(net_snap["source_ips"]),
        "os": sys_snap["os"],
        "platform": sys_snap["platform"],
        "status": "online",
        "cpu": sys_snap["cpu_percent"],
        "memory": sys_snap["memory_percent"],
        "disk": disk_snap["disk_percent"],
        "processes": sys_snap["process_count"],
        "uptime": sys_snap["uptime_seconds"],
        "environment": environment,
        "agent_id": ag,
    })
    db.save_server_stats(host, {
        "cpu": sys_snap["cpu_percent"],
        "memory": sys_snap["memory_percent"],
        "disk": disk_snap["disk_percent"],
        "network_mbps": net_snap["throughput_mbps"],
        "connections": net_snap["active_connections"],
        "connections_delta": net_snap["connection_count_delta"],
        "process_count": sys_snap["process_count"],
        "bytes_sent": net_snap["bytes_sent"],
        "bytes_recv": net_snap["bytes_recv"],
    })
    db.upsert_agent_heartbeat(ag, {
        "hostname": host,
        "ip": ",".join(net_snap["source_ips"]),
        "os": sys_snap["os"],
        "environment": environment,
        "version": f"collector-{settings.APP_VERSION}",
        "status": "HEALTHY",
    })

    # ------------------------------------------------------------------ #
    # 3. Outbound connections to external destinations.
    # ------------------------------------------------------------------ #
    for conn in monitor.connection_events():
        pipeline.ingest({
            "ts": now,
            "source": "collector",
            "host": host,
            "event_type": "net.connection",
            "category": "network",
            "severity": "info",
            "source_ip": conn["source_ip"],
            "dest_ip": conn["dest_ip"],
            "port": conn["dest_port"],
            "protocol": conn["protocol"],
            "process": str(conn.get("process_pid", "")),
            "details": {"status": conn.get("status"), "dest_port": conn["dest_port"],
                        "source_port": conn.get("source_port")},
        }, source="collector")

    # ------------------------------------------------------------------ #
    # 4. Process changes (new / exited).
    # ------------------------------------------------------------------ #
    new_procs, exited_procs = monitor.process_changes()
    for p in new_procs[:20]:
        pipeline.ingest({
            "ts": now,
            "source": "collector",
            "host": host,
            "event_type": "process.created",
            "category": "process",
            "severity": "low",
            "process": p.get("name", ""),
            "details": {"pid": p.get("pid"), "ppid": p.get("ppid"), "exe": p.get("exe", "")},
        }, source="collector")
    for p in exited_procs[:20]:
        pipeline.ingest({
            "ts": now,
            "source": "collector",
            "host": host,
            "event_type": "process.exited",
            "category": "process",
            "severity": "info",
            "process": p.get("name", ""),
            "details": {"pid": p.get("pid"), "exe": p.get("exe", "")},
        }, source="collector")

    # ------------------------------------------------------------------ #
    # 5. File changes (only when the interval elapsed).
    # ------------------------------------------------------------------ #
    if last_file_check and (time.monotonic() - last_file_check) >= FILE_INTERVAL:
        for fc in file_monitor.changes():
            suffix = fc.get("suffix", "")
            suspicious = suffix in {".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".pif"}
            pipeline.ingest({
                "ts": now,
                "source": "collector",
                "host": host,
                "event_type": f"file.{fc['action']}",
                "category": "file",
                "severity": "high" if (suspicious and fc["action"] == "created") else "info",
                "target": fc["path"],
                "details": {
                    "path": fc["path"],
                    "action": fc["action"],
                    "suffix": suffix,
                    "size": fc["size"],
                    "hash": fc["hash"],
                    "suspicious": suspicious,
                },
            }, source="collector")
