"""Standalone telemetry collectors — no FastAPI dependency.

Mirrors the collection logic in app.telemetry.system_monitor but is fully
self-contained for the standalone endpoint agent.
"""
import hashlib
import os
import platform
import socket
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import psutil

SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 53, 135, 139, 445, 1433, 1521, 3306, 3389,
    5432, 5900, 5984, 6379, 8080, 9200, 27017, 50070,
}
WELL_KNOWN = {80, 443, 53, 123, 67, 68, 993, 995, 587, 110, 143}

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "dist", ".pytest_cache", ".mypy_cache",
}

INTERESTING_SUFFIXES = {
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".jse", ".scr", ".pif", ".reg", ".doc", ".docx", ".xls", ".xlsx",
    ".pdf", ".zip", ".rar", ".7z", ".py", ".sh",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _local_ips() -> set[str]:
    out: set[str] = set()
    for _, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET:
                out.add(a.address)
    return out


# ── System ────────────────────────────────────────────────────────────────────

def collect_system() -> dict:
    cpu = psutil.cpu_percent(interval=0.2)
    vm = psutil.virtual_memory()
    load = {}
    try:
        l1, l5, l15 = psutil.getloadavg()
        load = {"1": round(l1, 2), "5": round(l5, 2), "15": round(l15, 2)}
    except (AttributeError, OSError):
        if platform.system() == "Windows":
            load = {}
    boot = psutil.boot_time()
    uptime = max(0.0, time.time() - boot)
    disk_total, disk_used = 0, 0
    partitions = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except OSError:
            continue
        disk_total += usage.total
        disk_used += usage.used
        partitions.append({
            "mount": part.mountpoint,
            "fs": part.fstype,
            "total_gb": round(usage.total / 1e9, 1),
            "used_gb": round(usage.used / 1e9, 1),
            "percent": round(usage.percent, 1),
        })
    disk_percent = round((disk_used / disk_total * 100), 1) if disk_total else 0.0
    return {
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "os": f"{platform.system()} {platform.release()}",
        "cpu_percent": round(cpu, 1),
        "memory_percent": round(vm.percent, 1),
        "memory_used_gb": round(vm.used / 1e9, 2),
        "memory_total_gb": round(vm.total / 1e9, 2),
        "load": load,
        "uptime_seconds": round(uptime, 1),
        "process_count": len(psutil.pids()),
        "disk_percent": disk_percent,
        "disk_partitions": partitions,
        "boot_time": datetime.fromtimestamp(boot, timezone.utc).isoformat(),
    }


# ── Network connections ───────────────────────────────────────────────────────

def collect_connections() -> list[dict]:
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        conns = []
    result = []
    for c in conns:
        try:
            laddr = c.laddr
            raddr = c.raddr
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            result.append({
                "local_addr": (laddr.ip, laddr.port) if laddr else None,
                "remote_addr": (raddr.ip, raddr.port) if raddr else None,
                "protocol": proto,
                "status": c.status,
                "pid": c.pid,
            })
        except Exception:
            continue
    return result


def collect_network_stats(prev_net, prev_ts) -> tuple[dict, object, float]:
    net_io = psutil.net_io_counters()
    now = time.monotonic()
    dt = max(now - prev_ts, 0.01)
    if prev_net is None:
        throughput = 0.0
    else:
        bytes_total = (
            (net_io.bytes_sent - prev_net.bytes_sent)
            + (net_io.bytes_recv - prev_net.bytes_recv)
        )
        throughput = max(0.0, bytes_total / dt) * 8 / 1e6
    return {
        "throughput_mbps": round(throughput, 2),
        "bytes_sent": net_io.bytes_sent,
        "bytes_recv": net_io.bytes_recv,
        "source_ips": list(_local_ips())[:20],
    }, net_io, now


# ── Process snapshot / change detection ───────────────────────────────────────

def collect_process_snapshot() -> dict[int, dict]:
    snap: dict[int, dict] = {}
    for p in psutil.process_iter(["pid", "name", "ppid", "exe", "create_time"]):
        try:
            snap[p.info["pid"]] = {
                "name": p.info["name"],
                "ppid": p.info["ppid"],
                "exe": p.info["exe"] or "",
                "created": p.info["create_time"],
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return snap


def detect_process_changes(prev: dict[int, dict]) -> tuple[list[dict], list[dict], dict[int, dict]]:
    current = collect_process_snapshot()
    new_procs = [{"pid": pid, **info} for pid, info in current.items() if pid not in prev]
    exited = [{"pid": pid, **info} for pid, info in prev.items() if pid not in current]
    return new_procs, exited, current


def top_processes(n: int = 8) -> list[dict]:
    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
        try:
            procs.append({
                "pid": p.info["pid"],
                "name": p.info["name"],
                "user": p.info["username"],
                "cpu": round(p.info["cpu_percent"] or 0.0, 1),
                "mem": round(p.info["memory_percent"] or 0.0, 1),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    procs.sort(key=lambda x: x["cpu"], reverse=True)
    return procs[:n]


# ── File monitoring ───────────────────────────────────────────────────────────

class FileMonitor:
    def __init__(self, roots: list[str]):
        self.roots = [Path(r) for r in roots]
        self._snapshot: dict[Path, dict[Path, dict]] = {}

    def _scan_root(self, root: Path) -> dict[Path, dict]:
        out: dict[Path, dict] = {}
        if not root.exists():
            return out
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                fp = Path(dirpath) / fn
                try:
                    st = fp.stat()
                    out[fp] = {
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                        "suffix": fp.suffix.lower(),
                        "hash": _quick_hash(fp, st),
                    }
                except OSError:
                    continue
        return out

    def changes(self) -> list[dict]:
        events = []
        for root in self.roots:
            current = self._scan_root(root)
            previous = self._snapshot.get(root, {})
            for fp, meta in current.items():
                if fp not in previous:
                    events.append({
                        "path": str(fp),
                        "action": "created",
                        "suffix": meta["suffix"],
                        "size": meta["size"],
                        "hash": meta["hash"],
                    })
                elif previous[fp]["mtime"] != meta["mtime"] or previous[fp]["size"] != meta["size"]:
                    events.append({
                        "path": str(fp),
                        "action": "modified",
                        "suffix": meta["suffix"],
                        "size": meta["size"],
                        "hash": meta["hash"],
                    })
            for fp in set(previous) - set(current):
                events.append({
                    "path": str(fp),
                    "action": "deleted",
                    "suffix": previous[fp]["suffix"],
                    "size": previous[fp]["size"],
                    "hash": previous[fp]["hash"],
                })
            self._snapshot[root] = current
        return events


def _quick_hash(fp: Path, st) -> str:
    try:
        h = hashlib.sha256()
        with open(fp, "rb") as f:
            h.update(f.read(262144))
            if st.st_size > 262144:
                f.seek(max(st.st_size - 262144, 0))
                h.update(f.read(262144))
        return h.hexdigest()[:32]
    except OSError:
        return ""
