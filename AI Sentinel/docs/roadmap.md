# AI Sentinel — Future Development Roadmap

## Near term (single-node hardening)

1. **Distributed event transport** — replace the in-process `asyncio.Queue`
   with Redis Streams (first) or Kafka/Redpanda, keeping `EventPipeline.ingest()`
   as the stable API. Enables multiple detection workers + multiple agents.
2. **Agent packaging** — installable endpoint agent (systemd / Windows service)
   pushing psutil + file + process + auth events to `/api/events/ingest/agent`
   with `X-Agent-Key`.
3. **MFA** — TOTP (pyotp) enrollment + enforcement for ADMIN/SOC roles,
   leveraging the existing token architecture.
4. **Alerting channels** — email (SMTP), Slack/Teams webhook, generic webhook
   with per-rule routing and retry/backoff.
5. **Response integrations** — concrete adapters for firewall blocking (iptables/
   pf/cloud security groups), EDR quarantine, session revocation, and backup
   snapshot protection, replacing dry-run stubs behind explicit enablement.

## Medium term

6. **Learned baselines per asset/user** — per-host and per-user profiles for
   request rates, login times, resource usage, and data volumes; feeds both the
   rule thresholds and the ML layer. DDoS/insider rules become baseline-aware.
7. **Behavioral risk scoring for users** — cumulative insider-threat scoring
   with human review gates (never auto-verdict from a single anomaly).
8. **Phishing deep analysis** — opt-in, sandboxed URL rendering to inspect
   TLS/SSL identity, page content, live redirects, and attachments; keep static
   fast-path for the default flow.
9. **Clustered storage** — Postgres/MySQL backend for the store with the same
   query API (parameterized layer already isolates SQL).
10. **Tamper-evident audit** — hash-chained audit log and read-only export for
    compliance.

## Long term

11. **Kubernetes deployment** — Helm chart: API, workers, Redis, Postgres;
    autoscaling by queue depth.
12. **Threat-intel feeds** — periodic IOC ingestion (MISP, STIX/TAXII), richer
    reputation scoring, and IOC lifecycle management.
13. **SOAR workflows** — playbook editor for incident response with
    approvals, SLAs, and full rollback/recovery automation.
14. **UI/UX** — threat map, drill-down analytics, saved views, notification
    preferences, and role-scoped workspaces.
15. **Multi-tenancy** — organization/tenant isolation for managed-service
    deployments.
16. **Compliance reporting** — evidence export aligned to SOC 2 / ISO 27001 /
    NIST guidance.

## Guiding principles (persist)

- Real telemetry only; demo mode explicit and off by default.
- Evidence-backed detections; no fabricated attacks or AI explanations.
- Rule + ML + TI layered, never ML-only.
- Destructive response actions always policy-gated, dry-run first, rollback
  documented.
