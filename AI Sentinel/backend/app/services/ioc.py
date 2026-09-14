"""IOC management service.

Indicator-of-Compromise management and real-time matching:

  * `match_event()` is called on the event-ingestion hot path (see pipeline).
    It extracts candidate indicators from the normalized event, looks them up
    against the managed IOC store (memory-cached, thread-safe), records each
    match, bumps `last_seen`, and raises a high-confidence alert when a
    malicious IOC matches (deduplicated per indicator within a window).

  * `import_iocs()` / `export_iocs()` provide STIX-lite CSV tooling for
    commercial onboarding of threat-intel feeds. Only detected rows are
    imported; every import is audited.

Honesty rules: verdicts come from the stored IOC; nothing is fabricated. If
IOC auto-alerting is disabled in config, `match_event` still records matches
but never raises alerts.
"""
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from app import db
from app.core.config import settings
from app.risk import risk_level
from app.services.notify import notify_alert

IOC_TYPES = ("ip", "domain", "url", "file", "sha256", "md5", "email", "host")
VALID_VERDICTS = ("malicious", "suspicious", "benign", "unknown")
VALID_TLPS = ("WHITE", "GREEN", "AMBER", "RED", "CLEAR")

# Field -> candidate value mapping on a normalized event.
_CANDIDATE_FIELDS = (
    ("ip", "source_ip"),
    ("ip", "dest_ip"),
    ("host", "host"),
    ("email", "username"),
)

_IOA_DETAIL_FIELDS = ("url", "domain", "hash", "file_hash", "sha256", "md5", "email", "file")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize(ioc_type: str, value: str) -> str:
    value = (value or "").strip().lower()
    if ioc_type == "url":
        value = value.rstrip("/")
    return value


class IOCService:
    def __init__(self):
        self._cache: dict[str, dict[str, dict]] = {}  # type -> {value: ioc}
        self._cache_at = 0.0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Lookup cache (bounded, thread-safe, TTL-refreshed)
    # ------------------------------------------------------------------ #
    def _refresh_cache(self, force: bool = False) -> None:
        with self._lock:
            if force or time.monotonic() - self._cache_at > settings.IOC_CACHE_TTL_SECONDS:
                rows = db.list_iocs(limit=100000, ioc_type=None)
                cache: dict[str, dict[str, dict]] = {}
                for row in rows:
                    cache.setdefault(row["ioc_type"], {})[row["ioc_value"]] = row
                self._cache = cache
                self._cache_at = time.monotonic()

    def lookup(self, ioc_type: str, value: str) -> Optional[dict]:
        """Look up a single normalized indicator (cached)."""
        normalized = _normalize(ioc_type, value)
        if not normalized:
            return None
        self._refresh_cache()
        with self._lock:
            found = self._cache.get(ioc_type, {}).get(normalized)
        return dict(found) if found else None

    # ------------------------------------------------------------------ #
    # Candidate extraction from a normalized event
    # ------------------------------------------------------------------ #
    def extract_candidates(self, event: dict) -> list[dict]:
        """Return [{ioc_type, value, field}] candidates present in the event.

        Fields are the normalized event columns plus string keys nested in the
        `details` object (urls, hashes, files).
        """
        candidates: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for ioc_type, field in _CANDIDATE_FIELDS:
            value = event.get(field)
            if value:
                candidates.append({"ioc_type": ioc_type, "value": str(value), "field": field})
                seen.add((ioc_type, str(value).strip().lower()))
        details = event.get("details") or {}
        if isinstance(details, dict):
            for field in _IOA_DETAIL_FIELDS:
                value = details.get(field)
                if not value:
                    continue
                ioc_type = field if field in ("url", "domain", "sha256", "md5") else (
                    "url" if field == "file_hash" else ("file" if field == "file" else "url"))
                ioc_type = "email" if field == "email" else ioc_type
                normalized = _normalize(ioc_type, str(value))
                if normalized and (ioc_type, normalized) not in seen:
                    candidates.append({"ioc_type": ioc_type, "value": str(value), "field": field})
                    seen.add((ioc_type, normalized))
        return candidates

    # ------------------------------------------------------------------ #
    # Ingress matching
    # ------------------------------------------------------------------ #
    def match_event(self, event: dict) -> list[dict]:
        """Match the event against managed IOCs; record + alert on hits.

        Returns the list of matched IOCs with `field`, `ioc_id`, `verdict` and
        `confidence`. Raises a deduplicated alert for malicious hits at or above
        the configured confidence threshold.
        """
        if not event.get("event_id"):
            return []
        self._refresh_cache()
        matches: list[dict] = []
        for cand in self.extract_candidates(event):
            ioc = self.lookup(cand["ioc_type"], cand["value"])
            if not ioc:
                continue
            entry = {
                "ioc_id": ioc["ioc_id"],
                "ioc_type": cand["ioc_type"],
                "ioc_value": cand["value"],
                "field": cand["field"],
                "verdict": ioc.get("verdict", "unknown"),
                "confidence": round(float(ioc.get("confidence", 0.0)), 3),
                "tags": ioc.get("tags", []),
                "source": ioc.get("source", ""),
            }
            db.record_ioc_match(ioc["ioc_id"], event["event_id"],
                                {"field": cand["field"], "event_type": event.get("event_type")})
            db.update_ioc(ioc["ioc_id"], last_seen=_now())
            if settings.IOC_AUTO_ALERT and entry["verdict"] == "malicious" \
                    and entry["confidence"] >= settings.IOC_MIN_ALERT_CONFIDENCE:
                self._raise_alert(event, entry)
            matches.append(entry)
        return matches

    def _raise_alert(self, event: dict, entry: dict) -> None:
        group_key = f"ioc|{entry['ioc_id']}"
        existing = db.find_open_alert_by_group(group_key, window_minutes=settings.IOC_ALERT_DEDUP_MINUTES)
        if existing:
            existing_ids = list(existing.get("event_ids", []))
            if event.get("event_id") and event["event_id"] not in existing_ids:
                existing_ids.append(event["event_id"])
                db.update_alert_event_ids(existing["alert_id"], existing_ids)
            return

        title = f"Known malicious IOC matched: {entry['ioc_type']} {entry['ioc_value']}"
        description = (f"Event {event.get('event_id')} (type={event.get('event_type')}) references a managed "
                       f"malicious indicator {entry['ioc_type']}={entry['ioc_value']} on field "
                       f"'{entry['field']}'. Confidence={entry['confidence']:.2f}, source={entry.get('source')}.")
        severity = "critical" if entry["confidence"] >= 0.8 else "high"
        alert = db.save_alert({
            "title": title,
            "description": description,
            "severity": severity,
            "risk_score": 90 if severity == "critical" else 70,
            "status": "NEW",
            "source": f"ioc:{entry['ioc_id']}",
            "event_ids": [event.get("event_id")],
            "group_key": group_key,
        })
        db.log_audit(actor="ioc-service", action="ioc.match.alert", result="SUCCESS",
                     target=alert["alert_id"],
                     detail={"ioc_id": entry["ioc_id"], "ioc_type": entry["ioc_type"],
                             "ioc_value": entry["ioc_value"], "event_id": event.get("event_id"),
                             "confidence": entry["confidence"]})
        try:
            notify_alert(alert)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Import / export
    # ------------------------------------------------------------------ #
    def import_iocs(self, rows: list[dict], actor: str = "") -> dict:
        """Import indicator rows. Each row: ioc_type, ioc_value, verdict,
        confidence, source, tags (optional). Returns per-type inserted/updated
        counters and any rejected rows with reasons."""
        imported = {"inserted": 0, "updated": 0, "rejected": 0}
        rejected: list[dict] = []
        for row in rows:
            ioc_type = str(row.get("ioc_type", "")).strip().lower()
            value = str(row.get("ioc_value", "")).strip()
            if ioc_type not in IOC_TYPES or not value:
                rejected.append({"row": row, "reason": "invalid or missing ioc_type/ioc_value"})
                imported["rejected"] += 1
                continue
            verdict = str(row.get("verdict", "unknown")).strip().lower()
            if verdict not in VALID_VERDICTS:
                rejected.append({"row": row, "reason": f"invalid verdict '{verdict}'"})
                imported["rejected"] += 1
                continue
            tags = row.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(";") if t.strip()]
            existing = db.get_ioc_by_value(ioc_type, value)
            db.save_ioc({
                "ioc_type": ioc_type,
                "ioc_value": value,
                "verdict": verdict,
                "confidence": min(1.0, max(0.0, float(row.get("confidence", 0.0) or 0.0))),
                "source": str(row.get("source", "import")) or "import",
                "tags": tags,
                "tlp": str(row.get("tlp", "WHITE")).upper(),
                "threat_actor": str(row.get("threat_actor", "")),
                "kill_chain_phase": str(row.get("kill_chain_phase", "")),
                "created_by": actor,
            })
            imported["updated" if existing else "inserted"] += 1
        db.log_audit(actor=actor, action="ioc.import", result="SUCCESS",
                     detail={"inserted": imported["inserted"], "updated": imported["updated"],
                             "rejected": imported["rejected"]})
        self._refresh_cache(force=True)
        return {**imported, "rejected_rows": rejected}

    def export_iocs(self, ioc_type: Optional[str] = None, verdict: Optional[str] = None) -> list[dict]:
        return db.list_iocs(limit=100000, ioc_type=ioc_type, verdict=verdict)


ioc_service = IOCService()