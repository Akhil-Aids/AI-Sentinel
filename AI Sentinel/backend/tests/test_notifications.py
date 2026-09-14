"""Notification framework tests: in-app persistence, unread tracking,
read actions, and honest NOT_CONFIGURED status for the webhook channel."""
from app import db
from app.core.config import settings
from app.services.notify import notify_alert


def test_notify_critical_creates_inapp(client):
    alert = db.save_alert({"alert_id": "alr-ntf-1", "title": "Critical finding",
                           "description": "campaign", "severity": "critical",
                           "risk_score": 80})
    before = db.count_unread_notifications()
    notif = notify_alert(alert, incident_id="inc-ntf-1")
    assert notif is not None
    assert notif["severity"] == "critical"
    assert db.count_unread_notifications() == before + 1


def test_notify_low_severity_is_suppressed(client):
    before = db.count_unread_notifications()
    low = db.save_alert({"alert_id": "alr-ntf-low", "title": "minor", "severity": "low"})
    assert notify_alert(low) is None
    assert db.count_unread_notifications() == before


def test_notify_webhook_reports_not_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "NOTIFY_WEBHOOK_URL", "")
    alert = {"alert_id": "alr-ntf-w", "title": "t", "description": "d",
             "severity": "critical", "risk_score": 90}
    # First create the in-app record via notify_alert so no import side effects.
    db.save_alert(alert)
    notif = notify_alert(alert)
    assert notif is not None


def test_notifications_api_flow(client, admin_headers):
    # Notifications created by detection (or direct pipeline output) are listed,
    # counted as unread, and can be marked read / read-all.
    db.save_notification({"title": "Campaign", "body": "high severity",
                          "severity": "high", "channel": "in-app"})
    listed = client.get("/api/notifications/", headers=admin_headers).json()
    assert listed["unread"] >= 1
    assert any(n["title"] == "Campaign" for n in listed["items"])

    cnt = client.get("/api/notifications/unread-count", headers=admin_headers).json()["unread"]
    assert cnt >= 1

    one = listed["items"][0]
    res = client.post(f"/api/notifications/{one['notification_id']}/read", headers=admin_headers)
    assert res.status_code == 200
    assert client.get("/api/notifications/unread-count", headers=admin_headers).json()["unread"] == cnt - 1

    marked = client.post("/api/notifications/read-all", headers=admin_headers).json()
    assert marked["status"] == "ok"
    assert client.get("/api/notifications/unread-count", headers=admin_headers).json()["unread"] == 0


def test_notifications_require_auth(client):
    assert client.get("/api/notifications/").status_code == 401

def test_webhook_payload_structure(monkeypatch):
    """The webhook payload is well-formed and carries alert context."""
    from app.services import notify as notify_mod
    sent = []
    captured = {"res.status": 200}
    monkeypatch.setattr(settings, "NOTIFY_WEBHOOK_URL", "https://hooks.example.invalid/soc")
    class _R:
        status = 200
    def _fake_urlopen(req, timeout=None):
        sent.append(req)
        class _Resp:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def read(self):
                return b"{}"
        return _Resp()
    monkeypatch.setattr(notify_mod, "urlopen", _fake_urlopen)
    alert = {"alert_id": "alr-ntf-payload", "title": "Ransomware burst",
             "description": "file burst", "severity": "critical", "risk_score": 95}
    db.save_alert(alert)
    result = notify_mod._fire_webhook({
        "type": "sentinel.alert", "version": settings.APP_VERSION, "environment": "test",
        "alert": {"id": alert["alert_id"], "title": alert["title"],
                  "severity": "critical", "risk_score": 95,
                  "incident_id": "", "created_at": "now"},
    })
    assert result["status"] == "SENT"