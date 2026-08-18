# AI Sentinel — AI / ML Architecture

## Model

- **Algorithm:** `IsolationForest` (scikit-learn), `n_estimators=150`,
  `contamination=SENTINEL_ML_CONTAMINATION` (default 0.05), `random_state=42`.
- **Preprocessing:** `StandardScaler` fit on the training set; the same scaler
  is applied at inference.
- **Persistence:** `backend/models/isolation_forest_network.joblib` +
  `…_scaler.joblib`; training metadata in the `model_state` table.

## Features (8)

| Feature | Source detail key |
|---|---|
| throughput_mbps | `throughput_mbps` |
| requests_per_sec | `requests_per_sec` |
| failed_logins | `failed_logins` |
| suspicious_ports_count | `suspicious_ports` (list) or `suspicious_ports_count` |
| active_connections | `active_connections` |
| cpu_percent | `cpu_percent` |
| memory_percent | `memory_percent` |
| disk_percent | `disk_percent` |

## Training lifecycle — why this is honest

The model is **not** trained repeatedly on the same live snapshot. Instead:

1. The telemetry collector emits real samples every 15 s; the pipeline calls
   `anomaly_detector.collect_sample(ev)`, which persists each sample as an
   `telemetry.sample` event in the store (real, accumulated history).
2. `needs_retrain()` counts `telemetry.sample` events newer than the last
   trained_at. When that count ≥ `SENTINEL_ML_RETRAIN_MIN_SAMPLES` (default
   200), a background loop (`_ml_retrain_loop`, every 10 min) trains on up to
   5000 historical samples.
3. Retraining requires ≥ 50 samples; otherwise it is skipped and reported.
4. After training, the model + scaler + baseline (mean/std/samples/trained_at)
   are persisted, and a new `model_state` version is recorded.

## Inference & explanation (no hallucination)

`score_event(ev)`:

- Returns `None` if ML is disabled, no model is loaded, or the event lacks the
  full feature set (silently skips, never invents data).
- Otherwise, `predict == -1` means anomaly. `confidence = clamp(1 - score, 0.5, 0.99)`.
- Severity: `>0.9` high, `>0.75` medium, else medium.

Explanations are derived from the actual baseline:
```
Anomaly: failed_logins is above normal baseline (observed 45.00, baseline mean 2.10);
active_connections is above normal baseline (observed 300.00, baseline mean 40.20).
Model trained on 420 historical samples.
```
Only features with |z| ≥ 2 are listed; if none, it says so plainly.

## ML in the pipeline

- ML is one detection layer. Rule-based detections and structural analyzers run
  regardless. An ML anomaly is appended to detections with `_ml: true`, gets a
  risk score (severity floor 40 for medium / 60 for high), and is surfaced in
  the dashboard with `ml: true` and the grounded `ai_explanation`.
- ML inference never blocks the API thread: it runs inside pipeline workers
  (`asyncio.to_thread`).

## Status / observability

`GET /api/system/metrics` and `/api/overview` expose `ml.status()`:
`{enabled, model_loaded, version, trained_samples, trained_at, contamination}`.

## Tuning

| Env | Purpose | Default |
|---|---|---|
| `SENTINEL_ML_ENABLED` | on/off | true |
| `SENTINEL_ML_RETRAIN_MIN_SAMPLES` | new samples needed before retrain | 200 |
| `SENTINEL_ML_CONTAMINATION` | assumed anomaly fraction | 0.05 |
