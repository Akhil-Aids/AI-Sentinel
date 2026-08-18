# AI Sentinel — Known Limitations

Status: 2026-08-16 (see `AUDIT_REPORT.md` and `VERIFICATION_REPORT.md` for
verification status of the rest of the system).

## Detection & data

1. **ML needs data volume.** The Isolation Forest only loads once ≥ 50 samples
   exist and retrains after ≥ 200 new samples (`SENTINEL_ML_RETRAIN_MIN_SAMPLES`).
   On a fresh install the ML layer is dormant until the telemetry collector has
   accumulated history. This is intentional (no fake training) but means early
   deployments rely on rules alone. No live anomaly verdict has been observed
   end-to-end yet (see verification report, item C7).
2. **Phishing analysis is static.** URLs are never fetched, so TLS identity,
   page content, live redirects, and attachment behavior are not inspected. The
   `redirects` list is always empty by design (safe).
3. **Threat-intelligence requires keys.** External IP/domain reputation needs
   `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` + `SENTINEL_TI_ENABLED=true`.
   Without keys only bundled local IOCs apply.
4. **DDoS rule is rate-based**, not a learned volumetric baseline. It detects
   request floods above threshold; sustained low-rate attacks may evade until
   the ML layer learns the baseline.
5. **Endpoint coverage is host-local.** Telemetry reflects the machine the
   backend runs on unless separate agents push events. Distributed agent
   deployment is a roadmap item.

## Correlation & incidents

6. **Incident correlation keys** (source IP / user / host, 6-hour window) can
   merge distinct campaigns sharing a NAT egress IP. Analysts should validate
   scope; false merges are possible.
7. **Alert dedup** uses `group_key = rule|source` within 30 minutes. A rule
   firing against multiple accounts from the same source collapses into one
   alert — desired for brute force, but it hides per-account granularity (the
   incident timeline retains per-event detail).

## Storage & scale

8. **Single-node SQLite + in-process queue** are not horizontally scalable.
   The latency tracker, queue depth, EPS and login rate limiter are all
   in-memory and reset on restart (queued events are lost on restart).
   High-volume deployments need Redis/Kafka + a clustered store (roadmap).
9. **No automatic purge of model files** — only event retention is applied;
   old `.joblib` versions accumulate in `backend/models/`.
10. **Latency tracker is transient.** SLA percentiles reflect the current
    process lifetime, not long-term history.

## Authentication & integrations

11. **No MFA enforcement yet** — the token architecture is MFA-ready, but
    TOTP/WebAuthn enrollment is not implemented.
12. **Response engine integrations** (firewall block, EDR quarantine, session
    revocation, backup snapshot triggers) are stubbed behind policies and
    blocked in dry-run. Destructive actions record but never execute; the
    approval flow is operator confirmation, not a separate approval role.
13. **Email/Slack/Teams/webhook alerting** is not wired up; dashboard + WS push
    only.

## Frontend

14. Dashboard requires the backend (Vite proxy or single-container static
    hosting). A standalone CDN deployment would need SPA build plus API/WS
    routing configured externally.
15. Push notifications and offline mode are not implemented.

## Security posture notes

16. Login rate limiter is in-memory per process — fine for a single instance,
    not for horizontally scaled deployments.
17. Audit log is append-only within SQLite but not cryptographically
    tamper-evident; a hardened audit service is a roadmap item.
18. Bootstrap admin password is written to `backend/bootstrap_admin.txt` until
    rotated after first login (audited).
