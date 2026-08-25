"""Real system telemetry collectors.

All metrics come from the actual operating system via psutil plus real
filesystem/process observation. No random values are injected anywhere.
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

from app.core.config import settings

# Ports commonly probed by scanners / exposed services.
SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 53, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5984, 6379, 8080, 9200, 27017, 50070,
}
WELL_KNOWN = {80, 443, 53, 123, 67, 68, 443, 993, 995, 587, 110, 143}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hostname() -> str:
    return socket.gethostname()


def _interface_ips() -> set:
    out = set()
    for snic, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET:
                out.add(a.address)
    return out


class SystemMonitor:
    """Samples real OS metrics. Safe to instantiate multiple times."""

    def __init__(self):
        self._prev_net = None
        self._prev_ts = time.monotonic()
        self._baseline_conns = 0
        self._prev_procs: dict = {}
        self._interface_ips = _interface_ips()

    # ------------------------------------------------------------------ #
    # System
    # ------------------------------------------------------------------ #
    def system_snapshot(self) -> dict:
        cpu = psutil.cpu_percent(interval=0.2)
        vm = psutil.virtual_memory()
        load = {}
        try:
            l1, l5, l15 = psutil.getloadavg()
            load = {"1": round(l1, 2), "5": round(l5, 2), "15": round(l15, 2)}
        except Exception:
            pass
        boot = psutil.boot_time()
        uptime = max(0, time.time() - boot)
        logged_in_users = []
        try:
            for u in psutil.users():
                logged_in_users.append({
                    "name": u.name,
                    "terminal": u.terminal or "",
                    "host": u.host or "",
                    "started": u.started,
                })
        except Exception:
            pass
        return {
            "hostname": hostname(),
            "platform": platform.system(),
            "os": f"{platform.system()} {platform.release()}",
            "cpu_percent": round(cpu, 1),
            "memory_percent": round(vm.percent, 1),
            "memory_used_gb": round(vm.used / 1e9, 2),
            "memory_total_gb": round(vm.total / 1e9, 2),
            "load": load,
            "uptime_seconds": round(uptime, 1),
            "process_count": len(psutil.pids()),
            "boot_time": datetime.fromtimestamp(boot, timezone.utc).isoformat(),
            "logged_in_users": logged_in_users,
        }

    def disk_snapshot(self) -> dict:
        total, used = 0, 0
        parts = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except Exception:
                continue
            total += usage.total
            used += usage.used
            parts.append({
                "mount": part.mountpoint,
                "fs": part.fstype,
                "total_gb": round(usage.total / 1e9, 1),
                "used_gb": round(usage.used / 1e9, 1),
                "percent": round(usage.percent, 1),
            })
        overall = round((used / total * 100), 1) if total else 0.0
        return {"disk_percent": overall, "partitions": parts}

    def top_processes(self, n: int = 8) -> list[dict]:
        procs = []
        for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "exe"]):
            try:
                procs.append({
                    "pid": p.info["pid"],
                    "name": p.info["name"],
                    "user": p.info["username"],
                    "cpu": round(p.info["cpu_percent"] or 0.0, 1),
                    "mem": round(p.info["memory_percent"] or 0.0, 1),
                    "exe": p.info["exe"] or "",
                })
            except Exception:
                continue
        procs.sort(key=lambda x: x["cpu"], reverse=True)
        return procs[:n]

    def process_snapshot(self) -> dict:
        """Full process map used to detect new / exited processes."""
        snapshot = {}
        for p in psutil.process_iter(["pid", "name", "ppid", "exe", "create_time"]):
            try:
                snapshot[p.info["pid"]] = {
                    "name": p.info["name"],
                    "ppid": p.info["ppid"],
                    "exe": p.info["exe"] or "",
                    "created": p.info["create_time"],
                }
            except Exception:
                continue
        return snapshot

    # ------------------------------------------------------------------ #
    # Network
    # ------------------------------------------------------------------ #
    def network_snapshot(self) -> dict:
        """Real network statistics derived from psutil connection tables + IO counters."""
        # Throughput: delta of bytes counters between samples.
        net_io = psutil.net_io_counters()
        now = time.monotonic()
        dt = max(now - self._prev_ts, 0.01)
        if self._prev_net is None:
            self._prev_net = net_io
            self._prev_ts = now
            throughput = 0.0
        else:
            bytes_total = (net_io.bytes_sent - self._prev_net.bytes_sent) + (net_io.bytes_recv - self._prev_net.bytes_recv)
            self._prev_net = net_io
            self._prev_ts = now
            throughput = max(0.0, bytes_total / dt) * 8 / 1e6  # Mbps

        connections = []
        ports_seen = defaultdict(int)
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            conns = []

        for c in conns:
            try:
                laddr = c.laddr
                raddr = c.raddr
                rec = {
                    "fd": c.fd,
                    "family": str(c.family),
                    "type": str(c.type),
                    "laddr": (laddr.ip, laddr.port) if laddr else None,
                    "raddr": (raddr.ip, raddr.port) if raddr else None,
                    "status": c.status,
                    "pid": c.pid,
                }
                if raddr and raddr.port:
                    ports_seen[raddr.port] += 1
                connections.append(rec)
            except Exception:
                continue

        if not self._baseline_conns:
            self._baseline_conns = len(connections)

        suspicious_ports = {p for p in ports_seen if p in SUSPICIOUS_PORTS}
        return {
            "throughput_mbps": round(throughput, 2),
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "active_connections": len(connections),
            "connection_count_delta": len(connections) - self._baseline_conns,
            "suspicious_ports": sorted(suspicious_ports),
            "source_ips": list(_interface_ips())[:20],
            "connections": connections[:400],
        }

    def connection_events(self) -> list[dict]:
        """Outbound connections to external destinations (candidate exfiltration/C2)."""
        snap = self.network_snapshot()
        out = []
        for c in snap["connections"]:
            raddr = c.get("raddr")
            laddr = c.get("laddr")
            if not raddr or not laddr:
                continue
            ip = raddr[0]
            port = raddr[1]
            if ip in self._interface_ips or ip.startswith(("127.", "0.0.0.0", "::1")):
                continue
            if port in WELL_KNOWN and port not in SUSPICIOUS_PORTS:
                continue
            out.append({
                "source_ip": laddr[0],
                "source_port": laddr[1],
                "dest_ip": ip,
                "dest_port": port,
                "protocol": "tcp",
                "status": c.get("status"),
                "process_pid": c.get("pid"),
            })
        # Deduplicate by (dest_ip, dest_port)
        seen = set()
        unique = []
        for r in out:
            key = (r["dest_ip"], r["dest_port"])
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique[:200]

    # ------------------------------------------------------------------ #
    # Process change detection
    # ------------------------------------------------------------------ #
    def process_changes(self) -> tuple[list[dict], list[dict]]:
        """Return (new_processes, exited_processes) since last sample."""
        current = self.process_snapshot()
        new_procs, exited_procs = [], []
        for pid, info in current.items():
            if pid not in self._prev_procs:
                new_procs.append({"pid": pid, **info})
        for pid, info in self._prev_procs.items():
            if pid not in current:
                exited_procs.append({"pid": pid, **info})
        self._prev_procs = current
        return new_procs, exited_procs


# --------------------------------------------------------------------------- #
# File monitoring (real, poll-based over configured directories)
# --------------------------------------------------------------------------- #
class FileMonitor:
    def __init__(self, roots: list[str] | None = None):
        self.roots = [Path(r) for r in (roots or settings.MONITOR_DIRS)]
        self._snapshot: dict[Path, dict] = {}
        self._interesting = {
            ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
            ".scr", ".pif", ".reg", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".zip", ".rar", ".7z",
            ".py", ".sh",
        }

    def _scan_root(self, root: Path) -> dict[Path, dict]:
        out: dict[Path, dict] = {}
        if not root.exists():
            return out
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", ".pytest_cache"}]
            for fn in filenames:
                fp = Path(dirpath) / fn
                try:
                    st = fp.stat()
                    out[fp] = {
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                        "suffix": fp.suffix.lower(),
                        "hash": self._quick_hash(fp, st),
                    }
                except OSError:
                    continue
        return out

    @staticmethod
    def _quick_hash(fp: Path, st) -> str:
        try:
            with open(fp, "rb") as f:
                # Hash first + last 256KB for speed; deterministic per file.
                f.seek(0)
                h = hashlib.sha256()
                h.update(f.read(262144))
                if st.st_size > 262144:
                    f.seek(max(st.st_size - 262144, 0))
                    h.update(f.read(262144))
                return h.hexdigest()[:32]
        except OSError:
            return ""

    def changes(self) -> list[dict]:
        """Detect created / modified / deleted / renamed files since last sample. Real data."""
        events = []
        for root in self.roots:
            current = self._scan_root(root)
            previous = self._snapshot.get(root, {})
            # Build hash -> path map for rename detection.
            prev_hashes: dict[str, str] = {}
            for fp, meta in previous.items():
                if meta["hash"]:
                    prev_hashes[meta["hash"]] = str(fp)
            seen_renames: set[str] = set()
            for fp, meta in current.items():
                if fp not in previous:
                    prev_path = prev_hashes.get(meta["hash"])
                    if prev_path and meta["hash"] and prev_path not in seen_renames:
                        events.append({
                            "path": str(fp),
                            "action": "renamed",
                            "old_path": prev_path,
                            "suffix": meta["suffix"],
                            "size": meta["size"],
                            "hash": meta["hash"],
                        })
                        seen_renames.add(prev_path)
                    else:
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
                if str(fp) not in seen_renames:
                    events.append({
                        "path": str(fp),
                        "action": "deleted",
                        "suffix": previous[fp]["suffix"],
                        "size": previous[fp]["size"],
                        "hash": previous[fp]["hash"],
                    })
            self._snapshot[root] = current
        return events


_system_monitor = SystemMonitor()
_file_monitor = FileMonitor()


def get_system_monitor() -> SystemMonitor:
    return _system_monitor


def get_file_monitor() -> FileMonitor:
    return _file_monitor
