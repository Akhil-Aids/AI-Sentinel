"""Notification framework.

Two channels:
  * in-app  - persisted notifications surfaced in the console (always active).
  * webhook - optional REST webhook POST, configured via SENTINEL_NOTIFY_WEBHOOK_URL.

The webhook channel explicitly reports NOT_CONFIGURED when no URL is set — the
system never pretends an unconfigured integration is active. Webhook delivery
runs in a background thread so detection latency is never blocked by a remote
call. Failures are logged to the audit trail.
"""
import json
import logging
import threading
from datetime import datetime, timezone
from urllib.request import Request, urlopen

from app import db
from app.core.config import settings

logger = logging.getLogger("sentinel.notify")

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _fire_webhook(payload: dict) -> dict:
    url = settings.NOTIFY_WEBHOOK_URL
    if not url:
        return {"channel": "webhook", "status": "NOT_CONFIGURED"}

    def _send():
        body = json.dumps(payload, default=str).encode("utf-8")
        try:
            req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(req, timeout=10) as resp:
                resp.read()
            db.log_audit(actor="system", action="notify.webhook", result="SUCCESS",
                         detail={"status_code": getattr(resp, "status", 0)})
        except Exception as exc:
            logger.warning("webhook delivery failed: %s", exc)
            db.log_audit(actor="system", action="notify.webhook", result="FAILED",
                         detail={"error": str(exc)})

    threading.Thread(target=_send, daemon=True).start()
    return {"channel": "webhook", "status": "SENT"}


def notify_alert(alert: dict, incident_id: str = "") -> dict | None:
    """Persist an in-app notification and fire optional webhook for an alert.

    Only alerts at or above settings.NOTIFY_MIN_SEVERITY raise notifications.
    """
    severity = alert.get("severity", "medium")
    min_severity = settings.NOTIFY_MIN_SEVERITY or "critical"
    if _SEVERITY_RANK.get(severity, 0) < _SEVERITY_RANK.get(min_severity, 3):
        return None

    notif = db.save_notification({
        "title": alert.get("title", "Security alert"),
        "body": alert.get("description", ""),
        "severity": severity,
        "channel": "in-app",
        "alert_id": alert.get("alert_id", ""),
        "incident_id": incident_id,
    })

    _fire_webhook({
        "type": "sentinel.alert",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "alert": {
            "id": alert.get("alert_id"),
            "title": alert.get("title"),
            "severity": severity,
            "risk_score": alert.get("risk_score", 0),
            "incident_id": incident_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    })
    return notif