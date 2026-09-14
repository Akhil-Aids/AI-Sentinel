"""(X8) Data quality center: pipeline integrity counts, ingest lag, evidence integrity."""
from datetime import datetime, timedelta, timezone

from app import db
from app.services import data_quality


def test_overview_endpoint(client, admin_headers):
    res = client.get("/api/data-quality/overview/", headers=admin_headers)
    assert res.status_code == 200, res.text
    body = res.json()
    assert {"overview", "by_source", "evidence_integrity", "recommendations"} <= body.keys()
    assert body["overview"]["total_ingested"] >= 0
    assert isinstance(body["evidence_integrity"]["by_status"], dict)


def test_event_counts_follow_ingestion():
    prev = data_quality.overview()["overview"]["total_ingested"]
    now = datetime.now(timezone.utc).isoformat()
    db.save_event({"event_id": "dq-ev-1", "event_type": "process.exec", "source": "agent",
                   "source_type": "endpoint", "severity": "info", "ts": now,
                   "ingested_at": now, "normalized_at": now, "processed_at": now})
    db.save_event({"event_id": "dq-ev-2", "event_type": "process.exec", "source": "agent",
                   "source_type": "endpoint", "severity": "info", "ts": now,
                   "ingested_at": now})
    curr = data_quality.overview()["overview"]
    assert curr["total_ingested"] >= prev + 2
    assert curr["normalized"] >= 1


def test_integrity_honest_when_empty(client, admin_headers):
    body = client.get("/api/data-quality/overview/", headers=admin_headers).json()
    # A store with zero traffic must never claim a clean feed.
    if body["overview"]["total_ingested"] == 0:
        assert any(r["type"] == "no_data" for r in body["recommendations"])


def test_lag_computation_units():
    now = datetime.now(timezone.utc)
    lag = (now - timedelta(seconds=50)).isoformat()
    db.save_event({"event_id": "dq-ev-lag", "event_type": "login", "source": "agent",
                   "source_type": "identity", "severity": "info", "ts": lag,
                   "ingested_at": lag, "normalized_at": lag})
    lag_sample = data_quality.overview()["overview"]["lag_seconds"]
    assert lag_sample is None or 0 <= lag_sample <= 120