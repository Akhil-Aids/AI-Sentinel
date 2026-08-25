"""Standalone endpoint agent entry point.

    cd backend
    python -m agent

No FastAPI dependency — uses only stdlib + psutil + urllib.
"""
import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from agent.config import config
from agent.collector import (
    SUSPICIOUS_PORTS,
    WELL_KNOWN,
    FileMonitor,
    collect_connections,
    collect_network_stats,
    collect_system,
    detect_process_changes,
    top_processes,
)

# ── Structured stderr logger ──────────────────────────────────────────────────

logger = logging.getLogger("sentinel.agent")
logger.setLevel(logging.DEBUG)
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(_handler)
_handler.stream = sys.stderr  # ensure stderr


def _log(level: str, msg: str, **extra: Any) -> None:
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "msg": msg,
        "agent_id": _AGENT_ID,
    }
    rec.update(extra)
    logger.log(getattr(logging, level.upper(), logging.INFO), json.dumps(rec, default=str))


# ── Agent identity ────────────────────────────────────────────────────────────

_AGENT_ID = f"agent-{config.HOSTNAME}-{uuid.uuid4().hex[:8]}"

# ── Global state ──────────────────────────────────────────────────────────────

_shutdown = threading.Event()

_prev_net = None
_prev_net_ts: float = time.monotonic()
_prev_procs: dict = {}
_last_file_check: float = 0.0

_buffer: list[dict] = []
_buffer_lock = threading.Lock()

_collector_health: dict[str, str] = {
    "system": "healthy",
    "network": "healthy",
    "process": "healthy",
    "file": "healthy",
}


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _http_post(url: str, payload: dict, timeout: float = 10.0) -> dict | None:
    body = json.dumps(payload, default=str).encode()
    req = Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Agent-Key": config.AGENT_KEY,
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        _log("warning", "http_error", url=url, status=e.code, detail=str(e))
        return None
    except (URLError, OSError, TimeoutError) as e:
        _log("warning", "http_unreachable", url=url, error=str(e))
        return None


def _retry_post(url: str, payload: dict) -> bool:
    delay = config.RETRY_BASE_DELAY
    while not _shutdown.is_set():
        result = _http_post(url, payload)
        if result is not None:
            return True
        _log("info", "retry_waiting", delay=round(delay, 1))
        _shutdown.wait(min(delay, 60))
        delay = min(delay * 2, config.RETRY_MAX_DELAY)
    return False


# ── Event helpers ─────────────────────────────────────────────────────────────

def _make_event(event_type: str, category: str, severity: str,
                details: dict, source: str = "endpoint-agent") -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "source_type": "endpoint-agent",
        "host": config.HOSTNAME,
        "environment": config.ENVIRONMENT,
        "asset_id": _AGENT_ID,
        "event_type": event_type,
        "category": category,
        "severity": severity,
        "details": details,
    }


def _buffer_event(event: dict) -> None:
    with _buffer_lock:
        if len(_buffer) >= config.BUFFER_MAX:
            _buffer.pop(0)
        _buffer.append(event)


def _drain_buffer() -> list[dict]:
    with _buffer_lock:
        batch = _buffer[:config.FLUSH_BATCH_SIZE]
        _buffer[:] = _buffer[config.FLUSH_BATCH_SIZE:]
    return batch


# ── Collectors ────────────────────────────────────────────────────────────────

_file_monitor = FileMonitor(config.PROTECTED_DIRS)


def _collect_cycle() -> None:
    global _prev_net, _prev_net_ts, _prev_procs, _last_file_check

    now_iso = lambda: datetime.now(timezone.utc).isoformat()

    # System
    try:
        sys_snap = collect_system()
        _collector_health["system"] = "healthy"
    except Exception as e:
        _collector_health["system"] = f"degraded: {e}"
        sys_snap = {}

    # Network
    try:
        net_stats, _prev_net, _prev_net_ts = collect_network_stats(_prev_net, _prev_net_ts)
        _collector_health["network"] = "healthy"
    except Exception as e:
        _collector_health["network"] = f"degraded: {e}"
        net_stats = {}

    # Connections
    try:
        connections = collect_connections()
    except Exception:
        connections = []

    # System + connections snapshot event
    if sys_snap:
        sys_snap["top_processes"] = top_processes()
        _buffer_event(_make_event(
            "telemetry.snapshot",
            "system",
            "info",
            {**sys_snap, "network": net_stats, "connection_count": len(connections)},
        ))

    # Connection events (suspicious destinations)
    local_ips = set(net_stats.get("source_ips", []))
    for conn in connections:
        raddr = conn.get("remote_addr")
        laddr = conn.get("local_addr")
        if not raddr or not laddr:
            continue
        ip = raddr[0]
        port = raddr[1]
        if ip in local_ips or ip.startswith(("127.", "0.0.0.0", "::1")):
            continue
        if port in WELL_KNOWN and port not in SUSPICIOUS_PORTS:
            continue
        _buffer_event(_make_event(
            "net.connection",
            "network",
            "info",
            {
                "source_ip": laddr[0],
                "source_port": laddr[1],
                "dest_ip": ip,
                "dest_port": port,
                "protocol": conn.get("protocol", "tcp"),
                "status": conn.get("status"),
                "process_pid": conn.get("pid"),
            },
        ))

    # Process changes
    try:
        new_procs, exited, _prev_procs = detect_process_changes(
            _prev_procs if _prev_procs else {}
        )
        _collector_health["process"] = "healthy"
        for p in new_procs[:20]:
            _buffer_event(_make_event(
                "process.created", "process", "low",
                {"pid": p.get("pid"), "name": p.get("name"), "ppid": p.get("ppid"), "exe": p.get("exe", "")},
            ))
        for p in exited[:20]:
            _buffer_event(_make_event(
                "process.exited", "process", "info",
                {"pid": p.get("pid"), "name": p.get("name"), "exe": p.get("exe", "")},
            ))
    except Exception as e:
        _collector_health["process"] = f"degraded: {e}"

    # File changes
    try:
        if _last_file_check and (time.monotonic() - _last_file_check) >= config.FILE_CHECK_INTERVAL:
            for fc in _file_monitor.changes():
                suspicious_ext = {".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".pif"}
                suspicious = fc.get("suffix", "") in suspicious_ext and fc["action"] == "created"
                _buffer_event(_make_event(
                    f"file.{fc['action']}",
                    "file",
                    "high" if suspicious else "info",
                    {
                        "path": fc["path"],
                        "action": fc["action"],
                        "suffix": fc["suffix"],
                        "size": fc["size"],
                        "hash": fc["hash"],
                        "suspicious": suspicious,
                    },
                ))
            _last_file_check = time.monotonic()
            _collector_health["file"] = "healthy"
        elif not _last_file_check:
            _last_file_check = time.monotonic()
    except Exception as e:
        _collector_health["file"] = f"degraded: {e}"


# ── Heartbeat ─────────────────────────────────────────────────────────────────

def _send_heartbeat() -> None:
    sys_snap = {}
    try:
        sys_snap = collect_system()
    except Exception:
        pass
    payload = {
        "agent_id": _AGENT_ID,
        "hostname": config.HOSTNAME,
        "ip": ",".join(sys_snap.get("source_ips", [])) if sys_snap else "",
        "os": sys_snap.get("os", ""),
        "environment": config.ENVIRONMENT,
        "version": f"endpoint-agent-1.0.0",
        "cpu": sys_snap.get("cpu_percent", 0.0),
        "memory": sys_snap.get("memory_percent", 0.0),
        "disk": sys_snap.get("disk_percent", 0.0),
        "processes": sys_snap.get("process_count", 0),
    }
    _retry_post(config.heartbeat_url, payload)


# ── Flush loop (thread) ──────────────────────────────────────────────────────

def _flush_loop() -> None:
    while not _shutdown.is_set():
        batch = _drain_buffer()
        if batch:
            payload = {"events": batch}
            success = _retry_post(config.ingest_url, payload)
            if not success:
                with _buffer_lock:
                    remaining = config.BUFFER_MAX - len(_buffer)
                    if remaining < len(batch):
                        _buffer[:] = _buffer[-remaining:]
                    _buffer.extend(batch)
                _log("warning", "flush_failed_buffer_restored", count=len(batch))
            else:
                _log("info", "flushed", count=len(batch))
        _shutdown.wait(1.0)


# ── Main loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    # Validate config
    try:
        config.validate()
    except ValueError as e:
        _log("error", "config_error", detail=str(e))
        sys.exit(1)

    # Signal handlers
    def _handle_signal(sig, _frame):
        _log("info", "signal_received", signal=sig)
        _shutdown.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    _log("info", "agent_starting", agent_id=_AGENT_ID, server=config.SERVER_URL)

    # Start flush thread
    flush_thread = threading.Thread(target=_flush_loop, daemon=True, name="flush")
    flush_thread.start()

    # Main collection loop
    heartbeat_due: float = 0.0
    while not _shutdown.is_set():
        _collect_cycle()

        now = time.monotonic()
        if now >= heartbeat_due:
            _send_heartbeat()
            heartbeat_due = now + config.HEARTBEAT_INTERVAL

        _shutdown.wait(config.COLLECT_INTERVAL)

    # Final flush
    _log("info", "shutting_down")
    batch = _drain_buffer()
    if batch:
        _http_post(config.ingest_url, {"events": batch}, timeout=5.0)
        _log("info", "final_flush", count=len(batch))

    _log("info", "agent_stopped")


if __name__ == "__main__":
    main()
