"""Authenticated WebSocket connection manager.

Clients authenticate by passing `?token=...` on the WebSocket URL or via the
`sentinel.<token>` Sec-WebSocket-Protocol subprotocol. The token is validated
against the same signed-token scheme as the REST API. Broadcasts are typed so
clients can route them. A `sent_at` timestamp is stamped on every message at
actual send time so end-to-end delivery latency can be measured.
"""
import json
from datetime import datetime, timezone
from typing import Any, List

from fastapi import WebSocket


class WSManager:
    def __init__(self):
        self.active: List[dict] = []

    async def connect(self, websocket: WebSocket, identity: dict):
        await websocket.accept()
        self.active.append({"ws": websocket, "identity": identity})

    def disconnect(self, websocket: WebSocket):
        self.active = [c for c in self.active if c["ws"] is not websocket]

    async def broadcast(self, message: dict):
        living = []
        for conn in list(self.active):
            ws = conn["ws"]
            out = dict(message)
            out["sent_at"] = datetime.now(timezone.utc).isoformat()
            try:
                await ws.send_json(out)
                living.append(conn)
            except Exception:
                pass
        self.active = living

    async def send_to(self, websocket: WebSocket, message: dict):
        try:
            await websocket.send_json(message)
        except Exception:
            pass

    def count(self) -> int:
        return len(self.active)

    def serialize(self) -> list[dict]:
        return [{"user": c["identity"].get("sub", "?"), "role": c["identity"].get("role", "?")} for c in self.active]


ws_manager = WSManager()
