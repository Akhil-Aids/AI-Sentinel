"""Demo mode tests.

Safety contracts:
  * generate_batch() is a no-op while SENTINEL_DEMO_MODE is false;
  * when enabled, every event is marked is_simulated=1, source=demo, and uses
    a demo- host prefix + RFC5737 test-net addresses;
  * the demo loop must not start unless demo mode is explicitly enabled.
"""
import pytest

from app.core.config import settings


def test_generate_batch_disabled_by_default():
    from app.telemetry.demo import generate_batch
    assert settings.DEMO_MODE is False
    assert generate_batch() == []


def test_generate_batch_enabled_marks_simulated(monkeypatch):
    monkeypatch.setattr(settings, "DEMO_MODE", True)
    import random
    from app.telemetry.demo import generate_batch, DEMO_ATTACKER_IPS, DEMO_BEACON_IPS, DEMO_HOSTS
    rng = random.Random(42)
    events = generate_batch(rng)
    assert events, "demo batch should produce events when enabled"
    for ev in events:
        assert ev["is_simulated"] == 1
        assert ev["source"] == "demo"
        assert ev["source_type"] == "simulation"
        assert ev["host"].startswith("demo-")
        if ev.get("source_ip"):
            assert ev["source_ip"] in DEMO_ATTACKER_IPS
        if ev.get("dest_ip"):
            assert ev["dest_ip"].startswith(("203.0.113.", "10.0."))
    # Every scenario emits telemetry snapshots for all demo hosts.
    snapshot_hosts = {e["host"] for e in events if e["event_type"] == "telemetry.snapshot"}
    assert snapshot_hosts == set(DEMO_HOSTS)


def test_demo_loop_noop_when_disabled(client):
    from app.telemetry.demo import run_demo_loop
    import asyncio
    async def _run():
        return await run_demo_loop()
    # When settings.DEMO_MODE is False the coroutine returns immediately.
    assert asyncio.run(_run()) is None


def test_demo_start_audit(client, admin_headers):
    """With demo mode disabled, no demo.start audit entries and no simulated
    events may leak into a non-demo store."""
    from app import db
    demo_events = db._fetch_all("SELECT * FROM events WHERE source = 'demo' OR is_simulated = 1 LIMIT 5")
    assert demo_events == [], "simulated events must never appear unless demo mode is enabled"
    audit = client.get("/api/system/audit?limit=50&actor=system", headers=admin_headers).json()["items"]
    assert not any(a["action"] == "demo.start" for a in audit), \
        "demo.start audit must only be written when demo mode is on"