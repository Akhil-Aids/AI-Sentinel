"""Demo-mode synthetic telemetry generator.

Explicitly opt-in via SENTINEL_DEMO_MODE=true (off by default). When active,
generates realistic-but-fake security telemetry that flows through the SAME
real detection pipeline as production, so demo alerts / incidents exercise the
identical rules, scoring and WebSocket broadcast path.

Safety rails:
  * every generated event sets is_simulated=1 and source="demo";
  * all hosts are namespaced with a `demo-` prefix;
  * documented TEST-NET ranges (RFC 5737: 198.51.100.0/24, 203.0.113.0/24)
    are used for attacker/beacon IPs so they can never collide with real hosts;
  * when demo mode is disabled every function is a no-op.
"""
import asyncio
import random
from datetime import datetime, timedelta, timezone

from app.core.config import settings

DEMO_HOSTS = ["demo-web-01", "demo-web-02", "demo-db-01", "demo-ws-01", "demo-webserver"]
DEMO_ATTACKER_IPS = ["198.51.100.17", "198.51.100.42", "198.51.100.99"]
DEMO_BEACON_IPS = ["203.0.113.5", "203.0.113.9", "203.0.113.44"]
DEMO_USERS = ["svc-web", "svc-db", "analyst.j", "admin.demo"]

SUSPICIOUS_BINARIES = ["mimikatz.exe", "psexec.exe", "procdump.exe", "invoke-mimikatz.ps1"]


def _now(delta_seconds: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=delta_seconds)).isoformat()


def _base(host: str, event_type: str, i: int = 0) -> dict:
    return {
        "event_id": f"demo-{event_type}-{host}-{datetime.now(timezone.utc).timestamp():.0f}-{i}",
        "ts": _now(i),
        "source": "demo",
        "source_type": "simulation",
        "host": host,
        "environment": settings.ENVIRONMENT,
        "is_simulated": 1,
        "event_type": event_type,
    }


def generate_batch(rng: random.Random | None = None) -> list[dict]:
    """Produce one demo batch. Empty when demo mode is disabled."""
    if not settings.DEMO_MODE:
        return []
    rng = rng or random.Random()
    events: list[dict] = []
    n = 0

    for host in DEMO_HOSTS:
        events.append({
            **_base(host, "telemetry.snapshot", n),
            "category": "system",
            "severity": "info",
            "details": {"cpu": rng.randint(3, 60), "memory": rng.randint(20, 80),
                        "disk": rng.randint(15, 85), "processes": rng.randint(120, 380)},
        })
        n += 1

    scenario = rng.choice(["bruteforce", "portscan", "ransomware", "exfiltration", "creds", "none"])
    src = rng.choice(DEMO_ATTACKER_IPS)
    target = rng.choice(DEMO_HOSTS)

    if scenario == "bruteforce":
        accounts = rng.sample(DEMO_USERS, k=3)
        for i in range(12):
            events.append({
                **_base(target, "auth.failed_login", n),
                "category": "authentication", "severity": "low",
                "source_ip": src, "username": accounts[i % 3],
                "details": {"reason": "invalid_credentials"},
            })
            n += 1
        events.append({
            **_base(target, "auth.successful_login", n),
            "category": "authentication", "severity": "info",
            "source_ip": src, "username": accounts[0],
            "details": {"method": "password"},
        })
        n += 1
    elif scenario == "portscan":
        for port in rng.sample(range(1, 65535), k=16):
            events.append({
                **_base(target, "net.connection", n),
                "category": "network", "severity": "info",
                "source_ip": src, "dest_ip": _local_ip(target, rng), "port": port,
                "protocol": rng.choice(["tcp", "tcp", "udp"]),
            })
            n += 1
    elif scenario == "ransomware":
        for i in range(22):
            etype = rng.choice(["file.created", "file.modified", "file.deleted", "file.renamed"])
            events.append({
                **_base(target, etype, n),
                "category": "file", "severity": "info",
                "username": rng.choice(["svc-web", "svc-db"]),
                "details": {"path": f"/opt/data/{rng.choice(['config','logs','db'])}/{i}.{rng.choice(['bak','log','db','dat'])}"},
            })
            n += 1
    elif scenario == "exfiltration":
        beacon = rng.choice(DEMO_BEACON_IPS)
        for i in range(32):
            events.append({
                **_base(target, "net.connection", n),
                "category": "network", "severity": "info",
                "source_ip": _local_ip(target, rng), "dest_ip": beacon,
                "port": rng.choice([443, 444, 8080, 53]), "protocol": "tcp",
            })
            n += 1
    elif scenario == "creds":
        events.append({
            **_base(target, "auth.privilege_change", n),
            "category": "identity", "severity": "medium",
            "username": "demo.admin", "target": "admin.demo",
            "details": {"granted_role": "ADMIN"},
        })
        n += 1
        if rng.random() < 0.5:
            events.append({
                **_base(target, "process.created", n),
                "category": "process", "severity": "medium",
                "username": "demo.admin",
                "process": rng.choice(SUSPICIOUS_BINARIES),
                "details": {"elevated": True},
            })
            n += 1

    return events


def _local_ip(host: str, rng: random.Random) -> str:
    return f"10.0.{rng.randint(1, 4)}.{rng.randint(2, 250)}"


async def run_demo_loop() -> None:
    """Background demo telemetry loop. No-op unless demo mode is enabled."""
    if not settings.DEMO_MODE:
        return
    from app import db
    from app.pipeline import pipeline

    rng = random.Random()
    # Register demo hosts so the console shows them as monitored assets.
    for host in DEMO_HOSTS:
        try:
            db.upsert_server(host, {
                "ip": _local_ip(host, rng),
                "os": "linux",
                "platform": "demo-simulated",
                "status": "online",
                "environment": settings.ENVIRONMENT,
            })
        except Exception:
            pass
    db.log_audit(actor="system", action="demo.start", result="SUCCESS",
                 detail={"interval_s": settings.DEMO_INTERVAL, "hosts": DEMO_HOSTS})

    while True:
        await asyncio.sleep(settings.DEMO_INTERVAL)
        try:
            events = generate_batch(rng)
            for ev in events:
                pipeline.ingest(ev, source="demo")
        except Exception:
            db.log_audit(actor="system", action="demo.generate", result="FAILED",
                         detail={"error": "demo batch error"})