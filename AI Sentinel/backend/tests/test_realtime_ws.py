"""Realtime WebSocket tests: subprotocol/query-token auth, bad-token rejection,
and live delivery of a detection to a connected dashboard client."""
import threading
import time

from conftest import TEST_PASSWORD, TEST_USERNAME


def _recv_json(ws, timeout=12.0):
    """Receive one JSON message with a hard timeout (sync TestClient blocks)."""
    out = {}

    def _recv():
        try:
            out["msg"] = ws.receive_json()
        except Exception as exc:  # pragma: no cover - failure path
            out["error"] = exc

    t = threading.Thread(target=_recv, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError("no WebSocket message within timeout")
    if "error" in out:
        raise out["error"]
    return out["msg"]


def _token(client):
    res = client.post("/api/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})
    assert res.status_code == 200
    return res.json()["token"]


def test_ws_rejects_bad_token(client):
    from starlette.websockets import WebSocketDisconnect
    try:
        with client.websocket_connect("/ws/events?token=garbage.token.here") as ws:
            _recv_json(ws, timeout=5.0)
        raise AssertionError("expected the server to close the connection")
    except WebSocketDisconnect as exc:
        assert exc.code == 4401


def test_ws_hello_and_detection_push(client):
    token = _token(client)
    with client.websocket_connect(f"/ws/events?token={token}") as ws:
        hello = _recv_json(ws)
        assert hello["type"] == "hello"
        assert hello["payload"]["user"]

        # Fire a brute-force campaign; the dashboard client should receive it live.
        events = [
            {"ts": f"2026-08-16T14:0{i}:00+00:00", "event_type": "auth.failed_login",
             "source_ip": "203.0.113.77", "username": f"u{i % 2}"}
            for i in range(12)
        ]
        res = client.post("/api/events/ingest", json={"events": events},
                          headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200

        deadline = time.time() + 15
        saw_detection = False
        while time.time() < deadline and not saw_detection:
            msg = _recv_json(ws)
            if msg["type"] == "detection":
                saw_detection = True
                payload = msg["payload"]
                assert payload["severity"]
                assert payload["dashboard_delivered_at"]
                assert "environment" in payload["event"]
                assert "is_simulated" in payload["event"]
                assert msg.get("sent_at")
        assert saw_detection, "expected a live detection pushed over the websocket"
