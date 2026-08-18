"""ML anomaly detection.

Isolation Forest trained on *accumulated historical telemetry* (persisted in
the event store), not on the same live snapshot repeatedly. Retraining happens
only when enough new samples have arrived. Every anomaly result carries an
explanation derived from the actual training baseline (mean/std) — no
hallucinated reasons.
"""
import math
import threading
import time
import uuid
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app import db
from app.core.config import settings

MODEL_NAME = "isolation_forest_network"


def new_sample_id() -> str:
    return f"mls_{uuid.uuid4().hex[:12]}"

FEATURE_NAMES = [
    "throughput_mbps", "connections_delta",
    "suspicious_ports_count", "active_connections",
    "cpu_percent", "memory_percent", "disk_percent",
]

# Map an event/details dict to a feature vector; missing features -> None.
FEATURE_EXTRACTORS = {
    "throughput_mbps": lambda d: d.get("throughput_mbps"),
    "connections_delta": lambda d: d.get("connections_delta", d.get("connection_count_delta")),
    "suspicious_ports_count": lambda d: len(d.get("suspicious_ports", [])) if isinstance(d.get("suspicious_ports"), list) else d.get("suspicious_ports_count"),
    "active_connections": lambda d: d.get("active_connections"),
    "cpu_percent": lambda d: d.get("cpu_percent"),
    "memory_percent": lambda d: d.get("memory_percent"),
    "disk_percent": lambda d: d.get("disk_percent"),
}


def _extract_vector(details: dict) -> list | None:
    vector = []
    for name in FEATURE_NAMES:
        value = FEATURE_EXTRACTORS[name](details)
        if value is None:
            return None
        try:
            vector.append(float(value))
        except (TypeError, ValueError):
            return None
    return vector


class AnomalyDetector:
    def __init__(self):
        self._model = None
        self._scaler = None
        self._baseline: dict = {}
        self._version = 0
        self._loaded_at = 0.0
        self._inference_latencies: list[float] = []  # bounded, ms
        self._inf_lat_lock = threading.Lock()

    def enabled(self) -> bool:
        return settings.ML_ENABLED

    def _load(self) -> None:
        if self._model is not None and time.time() - self._loaded_at < 30:
            return
        path = settings.MODEL_DIR / f"{MODEL_NAME}.joblib"
        scaler_path = settings.MODEL_DIR / f"{MODEL_NAME}_scaler.joblib"
        if path.exists() and scaler_path.exists():
            try:
                self._model = joblib.load(path)
                self._scaler = joblib.load(scaler_path)
                self._baseline = self._load_baseline()
                self._loaded_at = time.time()
                return
            except Exception:
                pass
        self._model = None
        self._scaler = None

    def _load_baseline(self) -> dict:
        state = db.latest_model_state(MODEL_NAME)
        if state:
            self._version = state.get("version", 0)
            params = state.get("params") or {}
            return {
                "mean": params.get("mean"),
                "std": params.get("std"),
                "samples": params.get("samples", 0),
                "trained_at": params.get("trained_at", ""),
                "version": state.get("version", 0),
            }
        return {}

    # ------------------------------------------------------------------ #
    # Training
    # ------------------------------------------------------------------ #
    def collect_sample(self, ev: dict) -> None:
        """Persist a real telemetry sample for future training."""
        if not self.enabled():
            return
        vector = _extract_vector(ev.get("details") or {})
        if vector is None:
            return
        sample = {
            "event_id": new_sample_id(),
            "ts": ev.get("ts"),
            "source": "telemetry.collector",
            "host": ev.get("host", ""),
            "event_type": "telemetry.sample",
            "category": "system",
            "severity": "info",
            "confidence": 0.0,
            "risk_score": 0,
            "details": {name: vector[i] for i, name in enumerate(FEATURE_NAMES)},
            "raw": {},
        }
        db.save_event(sample)

    def needs_retrain(self) -> bool:
        state = db.latest_model_state(MODEL_NAME)
        since = state["trained_at"] if state else None
        count = db._fetch_one(
            "SELECT COUNT(*) AS c FROM events WHERE event_type='telemetry.sample' AND ingested_at >= ?",
            (since,),
        )["c"] if since else db._fetch_one(
            "SELECT COUNT(*) AS c FROM events WHERE event_type='telemetry.sample'",
        )["c"]
        return count >= settings.ML_RETRAIN_MIN_SAMPLES

    def retrain(self) -> dict:
        """Train on historical telemetry samples. Called by a background job."""
        samples = db.query_events(minutes=None, limit=5000)
        vectors = []
        for s in samples:
            if s.get("event_type") != "telemetry.sample":
                continue
            v = _extract_vector(s.get("details") or {})
            if v:
                vectors.append(v)
        if len(vectors) < 50:
            return {"trained": False, "reason": "insufficient samples", "samples": len(vectors)}

        X = np.array(vectors, dtype=float)
        scaler = StandardScaler()
        Xs = scaler.fit_transform(X)
        model = IsolationForest(
            contamination=settings.ML_CONTAMINATION,
            random_state=42,
            n_estimators=150,
        )
        model.fit(Xs)

        settings.MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, settings.MODEL_DIR / f"{MODEL_NAME}.joblib")
        joblib.dump(scaler, settings.MODEL_DIR / f"{MODEL_NAME}_scaler.joblib")

        version = (db.latest_model_state(MODEL_NAME) or {}).get("version", 0) + 1
        mean = X.mean(axis=0).tolist()
        std = X.std(axis=0).tolist()
        params = {
            "mean": mean, "std": std, "samples": len(vectors),
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }
        metrics = self._eval_metrics(model, Xs)
        db.save_model_state(MODEL_NAME, version, len(vectors), params, metrics)

        self._model = model
        self._scaler = scaler
        self._baseline = {"mean": mean, "std": std, "samples": len(vectors),
                          "trained_at": params["trained_at"], "version": version}
        self._version = version
        return {"trained": True, "samples": len(vectors), "version": version, "metrics": metrics}

    @staticmethod
    def _eval_metrics(model, Xs: np.ndarray) -> dict:
        """Honest training diagnostics for an unsupervised model.

        There are no labels, so we report the anomaly rate the model learned,
        the distribution of decision scores (mean/std), and per-feature
        stability. These are diagnostics, not precision/recall — no labels exist
        for unsupervised anomaly detection.
        """
        scores = model.decision_function(Xs)
        preds = model.predict(Xs)
        anomaly_rate = float((preds == -1).mean())
        return {
            "anomaly_rate": round(anomaly_rate, 4),
            "decision_score_mean": round(float(scores.mean()), 4),
            "decision_score_std": round(float(scores.std()), 4),
            "decision_score_min": round(float(scores.min()), 4),
            "decision_score_max": round(float(scores.max()), 4),
            "n_estimators": model.n_estimators,
            "contamination": settings.ML_CONTAMINATION,
        }

    def drift_score(self) -> dict:
        """Feature-drift monitor: compare recent live samples against the baseline.

        Produces a normalized drift score (0-100) using mean z-score distance of
        recent samples from the trained baseline. No drift = 0.
        """
        self._load()
        mean = self._baseline.get("mean") or []
        std = self._baseline.get("std") or []
        if not mean or not std:
            return {"score": 0, "level": "unknown", "details": "Model not trained"}
        recent = db.query_events(minutes=30, limit=400)
        vectors = []
        for s in recent:
            if s.get("event_type") != "telemetry.sample":
                continue
            v = _extract_vector(s.get("details") or {})
            if v:
                vectors.append(v)
        if len(vectors) < 10:
            return {"score": 0, "level": "unknown", "details": "Insufficient recent samples"}
        X = np.array(vectors, dtype=float)
        recent_mean = X.mean(axis=0)
        diffs = []
        for i, name in enumerate(FEATURE_NAMES):
            if i >= len(mean) or i >= len(std):
                continue
            z = abs(recent_mean[i] - mean[i]) / (std[i] or 1e-9)
            diffs.append({"feature": name, "z": round(float(z), 3)})
        drift = float(np.mean([d["z"] for d in diffs]))
        score = min(100.0, drift * 20.0)
        level = "low" if score < 30 else ("medium" if score < 60 else "high")
        return {"score": round(score, 1), "level": level,
                "details": "Mean feature z-score vs training baseline", "features": sorted(diffs, key=lambda d: -d["z"])[:5]}

    # ------------------------------------------------------------------ #
    # Inference + explanation
    # ------------------------------------------------------------------ #
    def score_event(self, ev: dict) -> dict | None:
        if not self.enabled():
            return None
        self._load()
        if self._model is None or self._scaler is None:
            return None

        details = ev.get("details") or {}
        vector = _extract_vector(details)
        if vector is None:
            return None

        X = np.array([vector], dtype=float)
        start = time.monotonic()
        try:
            Xs = self._scaler.transform(X)
            pred = self._model.predict(Xs)[0]
            score = float(self._model.decision_function(Xs)[0])
        except Exception:
            return None
        self._record_inference_latency((time.monotonic() - start) * 1000.0)

        if pred != -1:
            return None

        confidence = float(min(0.99, max(0.5, 1.0 - score)))
        severity = "medium"
        if confidence > 0.9:
            severity = "high"
        elif confidence > 0.75:
            severity = "medium"

        explanation = self._explain(vector, details)
        return {
            "model": MODEL_NAME,
            "version": self._version or self._baseline.get("version", 0),
            "confidence": round(confidence, 2),
            "severity": severity,
            "explanation": explanation,
        }

    def _explain(self, vector: list[float], details: dict) -> str:
        mean = self._baseline.get("mean") or []
        std = self._baseline.get("std") or []
        if not mean or not std:
            return "The sample fell outside the learned baseline distribution (no further detail available)."
        parts = []
        for i, name in enumerate(FEATURE_NAMES):
            if i >= len(vector) or i >= len(mean) or i >= len(std):
                continue
            value = vector[i]
            mu, sigma = mean[i], (std[i] or 1e-9)
            z = (value - mu) / sigma
            if abs(z) >= 2.0:
                direction = "above" if z > 0 else "below"
                parts.append(f"{name} is {direction} normal baseline (observed {value:.2f}, baseline mean {mu:.2f})")
        if not parts:
            parts.append("the feature combination deviates from the learned baseline")
        baseline_note = f" Model trained on {int(self._baseline.get('samples', 0))} historical samples."
        return "Anomaly: " + "; ".join(parts[:5]) + "." + baseline_note

    def _record_inference_latency(self, ms: float) -> None:
        with self._inf_lat_lock:
            self._inference_latencies.append(ms)
            if len(self._inference_latencies) > 2000:
                self._inference_latencies = self._inference_latencies[-2000:]

    def inference_latency_ms(self) -> dict:
        with self._inf_lat_lock:
            vals = list(self._inference_latencies)
        if not vals:
            return {"samples": 0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0}
        vals.sort()
        n = len(vals)
        return {
            "samples": n,
            "p50_ms": round(vals[max(0, int(n * 0.50) - 1)], 2),
            "p95_ms": round(vals[max(0, int(n * 0.95) - 1)], 2),
            "p99_ms": round(vals[max(0, int(n * 0.99) - 1)], 2),
        }

    def status(self) -> dict:
        self._load()
        state = db.latest_model_state(MODEL_NAME)
        return {
            "enabled": self.enabled(),
            "model_loaded": self._model is not None,
            "version": self._version or self._baseline.get("version", 0),
            "trained_samples": int(self._baseline.get("samples", 0)),
            "trained_at": self._baseline.get("trained_at", ""),
            "contamination": settings.ML_CONTAMINATION,
            "metrics": (state or {}).get("metrics", {}),
            "drift": self.drift_score(),
            "inference_latency_ms": self.inference_latency_ms(),
        }


anomaly_detector = AnomalyDetector()
