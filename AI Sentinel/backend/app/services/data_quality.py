"""Data quality center: honest pipeline integrity, ingest health and evidence
integrity. Every number is computed live from the store; nothing is inferred.
"""
from collections import Counter
from datetime import datetime, timedelta, timezone

from app import db

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _epoch(ts: str) -> float | None:
    if not ts:
        return None
    try:
        parsed = datetime.fromisoformat(ts)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except Exception:
        return None


def _now_epoch() -> float:
    return datetime.now(timezone.utc).timestamp()


def overview() -> dict:
    events = db.list_events(limit=5000)
    total = len(events)
    normalized = sum(1 for e in events if e.get("normalized_at"))
    processed = sum(1 for e in events if e.get("processed_at"))
    errored = db.count_audit_errors(since=(datetime.now(timezone.utc) - timedelta(hours=24)).isoformat())
    unprocessed = total - processed

    # Events actually followed the pipeline to an incident/alert (or were matched).
    correlated = sum(1 for e in events if e.get("incident_created_at") or e.get("alert_created_at"))

    by_source = Counter()
    for e in events:
        src = e.get("source_type") or "unknown"
        by_source[src] += 1

    lag_samples = []
    for e in events[:2000]:
        ing = _epoch(e.get("ingested_at"))
        norm = _epoch(e.get("normalized_at"))
        if ing and ing > 0:
            lag_samples.append((norm - ing) if norm else (_now_epoch() - ing))
    lag_seconds = round(sum(lag_samples) / len(lag_samples), 1) if lag_samples else None

    quality = round(100 * normalized / total, 1) if total else None
    recommendations = []
    if total == 0:
        recommendations.append({"type": "no_data", "priority": "critical",
                                "recommendation": "No events have ever been ingested — feed a source first."})
    if errored:
        recommendations.append({"type": "ingest_errors", "priority": "high",
                                "recommendation": f"{errored} event(s) carry ingestion errors; inspect and re-queue."})
    if unprocessed:
        recommendations.append({"type": "backlog", "priority": "medium",
                                "recommendation": f"{unprocessed} event(s) not yet processed by the pipeline."})
    if lag_seconds is not None and lag_seconds > 60:
        recommendations.append({"type": "ingest_lag", "priority": "medium",
                                "recommendation": f"Average ingest→normalize lag is {lag_seconds}s; over 60s is late."})
    if quality is not None and quality < 90:
        recommendations.append({"type": "low_normalisation", "priority": "medium",
                                "recommendation": f"Only {quality}% of events are normalised; source coverage is thin."})

    return {
        "overview": {
            "total_ingested": total,
            "normalized": normalized,
            "processed": processed,
            "unprocessed": unprocessed,
            "errored": errored,
            "detection_matched": correlated,
            "normalisation_rate": quality,
            "lag_seconds": lag_seconds,
        },
        "by_source": [{"source": src, "events": n, "pct": round(100 * n / total, 1) if total else 0}
                      for src, n in by_source.most_common()],
        "evidence_integrity": evidence_integrity(),
        "recommendations": sorted(recommendations,
                                  key=lambda r: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(r["priority"], 3)),
    }


def evidence_integrity() -> dict:
    rows = db.list_evidence(limit=100000)
    counts = Counter(r.get("integrity_status", "NOT_APPLICABLE") for r in rows)
    return {
        "records": len(rows),
        "by_status": dict(counts),
        "verified": counts.get("VERIFIED", 0),
        "pending": counts.get("PENDING", 0),
        "tampered": counts.get("TAMPERED", 0),
    }