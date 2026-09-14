"""SOC metrics tests: MTTD/MTTA/MTTR computed from real persisted data.

Values must be None when insufficient data exists (never fabricated zeros) and
computed correctly once acknowledged/resolved records exist.
"""
from datetime import datetime, timedelta, timezone

from app import db
from app.services.metrics import (mean_time_to_acknowledge, mean_time_to_detect,
                                  mean_time_to_resolve, soc_metrics)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def test_metrics_structure(client):
    m = soc_metrics()
    for key in ("mttd", "mtta", "mttr_respond", "mttr_resolve"):
        assert key in m
        assert isinstance(m[key]["minutes"], (int, float, type(None)))
        assert isinstance(m[key]["samples"], int)
        assert m[key]["unit"] == "minutes"
        assert m[key]["label"]


def test_metric_returns_none_when_no_samples(monkeypatch):
    """When there are zero qualifying records, a metric must be None (not 0)."""
    import app.services.metrics as metrics_mod
    def _empty(*a, **kw):
        return []
    monkeypatch.setattr(metrics_mod.db, "_fetch_all", _empty)
    assert metrics_mod.mean_time_to_acknowledge()["minutes"] is None
    assert metrics_mod.mean_time_to_resolve()["minutes"] is None
    assert metrics_mod.mean_time_to_detect()["minutes"] is None
    assert metrics_mod.mean_time_to_acknowledge()["samples"] == 0


def test_mtta_computed_from_acknowledged_alert(client):
    now = datetime.now(timezone.utc)
    alert = db.save_alert({
        "alert_id": "alr-mtta-test",
        "title": "test", "description": "d", "severity": "high",
        "created_at": (now - timedelta(minutes=30)).isoformat(),
    })
    db.update_alert(alert["alert_id"], status="ACKNOWLEDGED",
                    acknowledged_at=now.isoformat())
    m = mean_time_to_acknowledge(days=30)
    assert m["samples"] >= 1
    assert 25.0 <= m["minutes"] <= 35.0


def test_mttr_computed_from_resolved_incident(client):
    now = datetime.now(timezone.utc)
    inc = db.save_incident({
        "incident_id": "inc-mttr-test",
        "title": "test", "severity": "high",
        "created_at": (now - timedelta(minutes=120)).isoformat(),
    })
    db.update_incident(inc["incident_id"], status="RESOLVED",
                       resolved_at=now.isoformat())
    m = mean_time_to_resolve(days=30)
    assert m["samples"] >= 1
    assert 110.0 <= m["minutes"] <= 130.0


def test_mttd_from_detected_event(client):
    before = mean_time_to_detect(days=7)["samples"]
    now = datetime.now(timezone.utc)
    db.save_event({
        "event_id": "evt-mttd-test",
        "ts": (now - timedelta(minutes=5)).isoformat(),
        "detected_at": now.isoformat(),
        "event_type": "auth.failed_login",
    })
    m = mean_time_to_detect(days=7)
    assert m["samples"] == before + 1
    assert m["minutes"] is not None and m["minutes"] >= 0.0


def test_metrics_reported_in_overview(client, admin_headers):
    res = client.get("/api/overview", headers=admin_headers)
    assert res.status_code == 200
    body = res.json()
    assert "soc_metrics" in body
    assert set(body["soc_metrics"]) >= {"mttd", "mtta", "mttr_respond", "mttr_resolve"}