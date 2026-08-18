"""Real-time event pipeline.

Event-driven architecture:
  Event source (agent / collector / API)
    -> Pipeline.ingest()  (non-blocking: enqueues and returns immediately)
    -> asyncio.Queue
    -> Worker(s): persist -> detection engine (rules + ML) -> threat intel
                  -> risk -> correlate -> alert/incident -> WebSocket broadcast

Queue decision: for a single-node deployment an in-process asyncio queue is
appropriate — it provides backpressure (maxsize), ordering, and non-blocking
ingestion with zero external infrastructure. The pipeline is deliberately
isolated in `EventPipeline` so a Redis/Kafka transport can replace the queue
later for multi-node deployments without changing callers.
"""
import asyncio
import statistics
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from app import db
from app.core.config import settings
from app.correlate import correlator
from app.engines import build_detection_engine
from app.engines.rules import seed_default_rules
from app.ml.anomaly import anomaly_detector
from app.pipeline.normalize import normalize_raw
from app.risk import event_risk, risk_level
from app.services.ws_manager import ws_manager
from app import threat_intel

_QUEUE: Optional[asyncio.Queue] = None

MAX_LATENCY_SAMPLES = 2000


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class LatencyTracker:
    """In-memory end-to-end latency samples (event ingested -> WS delivered).

    Transient by design: latency is an observability signal for a single-node
    deployment, not durable security data. Provides p50/p95/p99 and a target
    compliance rate against the configured SLAs.
    """

    def __init__(self):
        self._samples: deque[float] = deque(maxlen=MAX_LATENCY_SAMPLES)
        self._critical: deque[float] = deque(maxlen=MAX_LATENCY_SAMPLES)
        self._lock = threading.Lock()

    def record(self, latency_ms: float, severity: str = "info") -> None:
        with self._lock:
            self._samples.append(latency_ms)
            if severity == "critical":
                self._critical.append(latency_ms)

    def summary(self) -> dict:
        def _pct(values, p):
            if not values:
                return 0.0
            return round(statistics.quantiles(values, n=100, method="inclusive")[p - 1], 2)

        with self._lock:
            all_s = list(self._samples)
            crit = list(self._critical)
        n = len(all_s)
        met_all = sum(1 for s in all_s if s <= settings.LATENCY_TARGET_EVENT_MS)
        met_crit = sum(1 for s in crit if s <= settings.LATENCY_TARGET_CRITICAL_MS)
        return {
            "samples": n,
            "target_event_ms": settings.LATENCY_TARGET_EVENT_MS,
            "target_critical_ms": settings.LATENCY_TARGET_CRITICAL_MS,
            "p50_ms": _pct(all_s, 50),
            "p95_ms": _pct(all_s, 95),
            "p99_ms": _pct(all_s, 99),
            "max_ms": round(max(all_s), 2) if all_s else 0.0,
            "sla_met_pct": round(100.0 * met_all / n, 1) if n else 100.0,
            "critical_sla_met_pct": round(100.0 * met_crit / len(crit), 1) if crit else 100.0,
        }


latency_tracker = LatencyTracker()


class EventPipeline:
    def __init__(self, workers: int = 2):
        self.workers = workers
        self._tasks: list[asyncio.Task] = []
        self._started = False
        self._event_counter = 0
        self._window_start = time.monotonic()
        self._window_events = 0
        self._eps = 0.0
        self._processed = 0
        self._deduplicated = 0
        self._last_broadcast = 0.0
        self.detection_engine = build_detection_engine(ml=anomaly_detector)
        # Serializes alert-dedup + correlation so concurrent workers cannot
        # create duplicate incidents for the same campaign.
        self._det_lock = threading.Lock()
        self._loop = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if self._started:
            return
        self._started = True
        global _QUEUE
        _QUEUE = asyncio.Queue(maxsize=settings.QUEUE_MAXSIZE)
        seed_default_rules()
        threat_intel.seed_local_iocs()
        self._loop = asyncio.get_event_loop()
        for i in range(self.workers):
            self._tasks.append(asyncio.create_task(self._worker(i)))

    def _broadcast(self, message: dict) -> None:
        """Schedule a WS broadcast on the main event loop (thread-safe)."""
        loop = getattr(self, "_loop", None)
        if loop is None or loop.is_closed():
            return
        try:
            asyncio.run_coroutine_threadsafe(ws_manager.broadcast(message), loop)
        except Exception:
            pass

    async def stop(self) -> None:
        self._started = False
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass

    def queue_depth(self) -> int:
        return _QUEUE.qsize() if _QUEUE is not None else 0

    # ------------------------------------------------------------------ #
    # Ingest
    # ------------------------------------------------------------------ #
    def ingest(self, raw: dict, source: str = "agent") -> bool:
        """Non-blocking ingestion. Returns True if the event was enqueued."""
        if _QUEUE is None or not self._started:
            return False
        try:
            _QUEUE.put_nowait({"raw": raw, "source": source, "enqueued_at": time.monotonic()})
            return True
        except asyncio.QueueFull:
            db.log_audit(actor="system", action="pipeline.queue_full", result="FAILED",
                         detail={"source": source})
            return False

    # ------------------------------------------------------------------ #
    # Worker
    # ------------------------------------------------------------------ #
    async def _worker(self, index: int) -> None:
        while True:
            item = await _QUEUE.get()
            try:
                await asyncio.to_thread(self._process, item)
            except Exception as exc:
                db.log_audit(actor=f"worker-{index}", action="pipeline.process_error",
                             result="FAILED", detail={"error": str(exc)})
            finally:
                _QUEUE.task_done()

    def _process(self, item: dict) -> None:
        raw, source = item["raw"], item["source"]
        enqueued_at = item.get("enqueued_at")
        ev = normalize_raw(raw, source=source)
        ev = db.save_event(ev)
        ev["processed_at"] = _utcnow_iso()
        db.update_event_latencies(ev["event_id"], processed_at=ev["processed_at"])

        # Maintain EPS metric.
        self._track_rate()

        if ev.get("_deduplicated"):
            self._deduplicated += 1
            # Duplicate replay of an already-processed event: do not re-detect.
            self._maybe_broadcast_stats()
            return

        # Collect real telemetry samples for ML training.
        if ev.get("event_type") in {"telemetry.snapshot", "server.metrics"}:
            anomaly_detector.collect_sample(ev)

        # Detection engine (rules + structural + ML).
        result = self.detection_engine.analyze(ev)
        detections = result.get("detections", [])
        ml_anomaly = result.get("ml_anomaly")

        if detections or ml_anomaly:
            ev["detected_at"] = _utcnow_iso()
            db.update_event_latencies(ev["event_id"], detected_at=ev["detected_at"])

        # If ML flags an anomaly, treat it as a detection as well.
        if ml_anomaly:
            detections.append({
                "event_id": ev.get("event_id"),
                "rule_id": "ml_anomaly",
                "rule_name": "ML behavioral anomaly",
                "description": ml_anomaly.get("explanation", "Behavior outside learned baseline."),
                "category": "generic",
                "severity": ml_anomaly.get("severity", "medium"),
                "mitre": [],
                "source_ip": ev.get("source_ip", ""),
                "dest_ip": ev.get("dest_ip", ""),
                "host": ev.get("host", ""),
                "username": ev.get("username", ""),
                "confidence": ml_anomaly.get("confidence", 0.0),
                "_ml": True,
            })

        if not detections:
            # Keep the pipeline warm but only broadcast notable events if enabled.
            self._maybe_broadcast_stats()
            return

        for detection in detections:
            self._handle_detection(ev, detection, ml_anomaly, enqueued_at)

        self._maybe_broadcast_stats()

    def _handle_detection(self, ev: dict, detection: dict, ml_anomaly: dict | None,
                          enqueued_at: float | None = None) -> None:
        with self._det_lock:
            return self._handle_detection_locked(ev, detection, ml_anomaly, enqueued_at)

    def _handle_detection_locked(self, ev: dict, detection: dict, ml_anomaly: dict | None,
                                 enqueued_at: float | None = None) -> None:
        correlated_at = _utcnow_iso()
        db.update_event_latencies(ev["event_id"], correlated_at=correlated_at)

        # Threat intelligence contribution.
        ti = 0.0
        if ev.get("source_ip"):
            ti = threat_intel.ti_bonus("ip", ev["source_ip"])
        if ev.get("dest_ip"):
            ti = max(ti, threat_intel.ti_bonus("ip", ev["dest_ip"]))

        risk = event_risk(ev, ti_bonus=ti if detection.get("_ml") else 0.0)
        risk = max(risk, detection_severity_floor(detection.get("severity", "medium")))

        # Alert dedup: collapse repeated firings of the same rule against the same
        # attacker/asset into a single open alert within the window.
        group_key = "|".join([
            detection.get("rule_id", "unknown"),
            ev.get("source_ip", "") or ev.get("host", "") or ev.get("username", "") or "unknown",
        ])
        existing = db.find_open_alert_by_group(group_key)

        alert = None
        if existing:
            existing_event_ids = list(existing.get("event_ids", []))
            if ev.get("event_id") and ev["event_id"] not in existing_event_ids:
                existing_event_ids.append(ev["event_id"])
            db.update_alert_event_ids(existing["alert_id"], existing_event_ids)
        else:
            # Persist detection as an alert-level finding.
            alert_created_at = _utcnow_iso()
            alert = db.save_alert({
                "title": detection.get("rule_name", "Detection"),
                "description": detection.get("description", ""),
                "severity": detection.get("severity", "medium"),
                "risk_score": risk,
                "status": "NEW",
                "source": detection.get("rule_id", "unknown"),
                "event_ids": [ev.get("event_id")],
                "group_key": group_key,
            })
            db.update_event_latencies(ev["event_id"], alert_created_at=alert_created_at)

        ai_explanation = ml_anomaly.get("explanation", "") if ml_anomaly else ""

        # Correlate into an incident.
        incident = correlator.correlate(detection, ev, ti_bonus=ti, ai_explanation=ai_explanation,
                                        risk_score=risk)
        db.update_event_latencies(ev["event_id"], incident_created_at=_utcnow_iso())

        # Backfill the originating phishing scan with its incident link.
        if ev.get("event_type") == "phishing.detected":
            details = ev.get("details") or {}
            if details.get("url"):
                db.link_phishing_scan_to_incident(details["url"], incident["incident_id"])

        if not alert:
            # Deduplicated event appended to the existing alert; still broadcast
            # a lightweight update so live dashboards stay current.
            db.log_audit(actor="detection-engine", action=f"detect.{detection.get('category', 'unknown')}",
                         result="SUCCESS", target=existing["alert_id"],
                         detail={"rule": detection.get("rule_id"), "incident_id": incident["incident_id"],
                                 "dedup": True})
            self._maybe_broadcast_stats()
            return

        # Broadcast in real time (thread-safe; scheduled on the main loop).
        delivered_at = _utcnow_iso()
        db.update_event_latencies(ev["event_id"], dashboard_delivered_at=delivered_at)
        if enqueued_at:
            latency_ms = round((time.monotonic() - enqueued_at) * 1000.0, 2)
            latency_tracker.record(latency_ms, severity=alert["severity"])
        msg = {
            "type": "detection",
            "payload": {
                "alert_id": alert["alert_id"],
                "incident_id": incident["incident_id"],
                "title": alert["title"],
                "description": alert["description"],
                "severity": alert["severity"],
                "risk_score": risk,
                "risk_level": risk_level(risk),
                "rule": detection.get("rule_name"),
                "category": detection.get("category"),
                "mitre": detection.get("mitre", []),
                "dashboard_delivered_at": delivered_at,
                "event": {
                    "event_id": ev.get("event_id"),
                    "type": ev.get("event_type"),
                    "time": ev.get("ts"),
                    "host": ev.get("host"),
                    "environment": ev.get("environment", ""),
                    "is_simulated": ev.get("is_simulated", 0),
                    "source_ip": ev.get("source_ip"),
                    "dest_ip": ev.get("dest_ip"),
                    "username": ev.get("username"),
                },
                "ml": ml_anomaly is not None,
                "ai_explanation": ai_explanation,
            },
        }
        self._broadcast(msg)

        db.log_audit(actor="detection-engine", action=f"detect.{detection.get('category','unknown')}",
                     result="SUCCESS", target=alert["alert_id"],
                     detail={"rule": detection.get("rule_id"), "incident_id": incident["incident_id"]})

    def _track_rate(self) -> None:
        self._event_counter += 1
        now = time.monotonic()
        if now - self._window_start >= 5:
            self._eps = (self._event_counter - self._window_events) / (now - self._window_start)
            self._window_events = self._event_counter
            self._window_start = now

    def _maybe_broadcast_stats(self) -> None:
        now = time.monotonic()
        if now - self._last_broadcast < 2:
            return
        self._last_broadcast = now
        self._broadcast({"type": "stats", "payload": self.stats()})

    def stats(self) -> dict:
        return {
            "eps": round(self._eps, 2),
            "processed": self._event_counter,
            "deduplicated": self._deduplicated,
            "queue_depth": self.queue_depth(),
            "ws_connections": ws_manager.count(),
            "detections_today": db.count_alerts(),
            "latency": latency_tracker.summary(),
        }


def detection_severity_floor(severity: str) -> int:
    return {"low": 20, "medium": 40, "high": 60, "critical": 80}.get(severity, 0)


pipeline = EventPipeline(workers=settings.WORKER_CONSUMERS)
