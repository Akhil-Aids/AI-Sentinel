"""AI Sentinel API entrypoint."""
import asyncio
import secrets
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app import db
from app.core.config import WORKSPACE_ROOT, settings, validate_settings
from app.core.security import hash_password, decode_token
from app.pipeline import pipeline
from app.services.ws_manager import ws_manager
from app.telemetry.collector import run_collector_loop

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def bootstrap_admin() -> None:
    """Create the initial admin account if none exists.

    Password: SENTINEL_ADMIN_PASSWORD env var, else a generated random value
    written to backend/bootstrap_admin.txt. Never 'admin/admin'.
    """
    if db.count_users() > 0:
        return
    username = "admin"
    password = settings.ADMIN_PASSWORD or secrets.token_urlsafe(12)
    db.create_user(username, hash_password(password), "ADMIN", "Bootstrap Administrator")
    if not settings.ADMIN_PASSWORD:
        out = Path(__file__).resolve().parent / "bootstrap_admin.txt"
        out.write_text(f"username={username}\npassword={password}\n\nRotate this password after first login.\n", encoding="utf-8")
        print(f"[bootstrap] Admin created. Password written to {out}")
    else:
        print("[bootstrap] Admin account created from environment variables.")
    db.log_audit(actor="system", action="auth.bootstrap_admin", result="SUCCESS",
                 detail={"username": username})


async def _retention_loop() -> None:
    while True:
        await asyncio.sleep(3600 * 24)
        try:
            db.apply_retention(settings.RETENTION_DAYS)
        except Exception as exc:
            db.log_audit(actor="system", action="retention.apply", result="FAILED", detail={"error": str(exc)})


async def _ml_retrain_loop() -> None:
    from app.ml.anomaly import anomaly_detector
    while True:
        await asyncio.sleep(60 * 10)
        try:
            if anomaly_detector.needs_retrain():
                await asyncio.to_thread(anomaly_detector.retrain)
        except Exception as exc:
            db.log_audit(actor="system", action="ml.retrain", result="FAILED", detail={"error": str(exc)})


@app.on_event("startup")
def startup() -> None:
    validate_settings()
    db.init_schema()
    bootstrap_admin()
    pipeline.start()
    asyncio.get_event_loop().create_task(run_collector_loop())
    asyncio.get_event_loop().create_task(_retention_loop())
    asyncio.get_event_loop().create_task(_ml_retrain_loop())
    print(f"{settings.APP_NAME} v{settings.APP_VERSION} started "
          f"(env={settings.ENV}, storage={settings.DB_PATH}, demo_mode={settings.DEMO_MODE})")


@app.on_event("shutdown")
def shutdown() -> None:
    try:
        loop = asyncio.get_event_loop()
        loop.create_task(pipeline.stop())
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Routers
# --------------------------------------------------------------------------- #
from app.routes.auth import router as auth_router  # noqa: E402
from app.routes.alerts import router as alerts_router  # noqa: E402
from app.routes.agents import router as agents_router  # noqa: E402
from app.routes.chatbot import router as chatbot_router  # noqa: E402
from app.routes.events import router as events_router  # noqa: E402
from app.routes.health import router as health_router  # noqa: E402
from app.routes.incidents import router as incidents_router  # noqa: E402
from app.routes.network import router as network_router  # noqa: E402
from app.routes.overview import router as overview_router  # noqa: E402
from app.routes.phishing import router as phishing_router  # noqa: E402
from app.routes.rules import router as rules_router  # noqa: E402

app.include_router(auth_router, prefix="/api/auth", tags=["Auth"])
app.include_router(overview_router, prefix="/api", tags=["Overview"])
app.include_router(events_router, prefix="/api/events", tags=["Events"])
app.include_router(incidents_router, prefix="/api/incidents", tags=["Incidents"])
app.include_router(alerts_router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(network_router, prefix="/api/network", tags=["Network"])
app.include_router(rules_router, prefix="/api/rules", tags=["Rules"])
app.include_router(phishing_router, prefix="/api/phishing", tags=["Phishing"])
app.include_router(chatbot_router, prefix="/api/chatbot", tags=["Chatbot"])
app.include_router(health_router, prefix="/api/system", tags=["System"])
app.include_router(agents_router, prefix="/api/agents", tags=["Agents"])


# --------------------------------------------------------------------------- #
# Public health (no auth)
# --------------------------------------------------------------------------- #
@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "ai-sentinel", "version": settings.APP_VERSION,
            "demo_mode": settings.DEMO_MODE}


# --------------------------------------------------------------------------- #
# Authenticated WebSocket event stream
# --------------------------------------------------------------------------- #
@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket, token: str = ""):
    """Authenticated live event stream.

    Token may be supplied as a Sec-WebSocket-Protocol subprotocol header
    (`sentinel.<token>`, keeps the token out of the URL) or via the legacy
    `?token=` query parameter (kept for backward compatibility).
    """
    auth_token = token or _token_from_subprotocol(websocket)
    if not auth_token:
        await websocket.close(code=4401)
        return
    try:
        identity = decode_token(auth_token)
    except Exception:
        await websocket.close(code=4401)
        return
    await ws_manager.connect(websocket, identity)
    try:
        await websocket.send_json({"type": "hello", "payload": {"user": identity.get("sub")}})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


def _token_from_subprotocol(websocket: WebSocket) -> str:
    for sub in websocket.headers.get_list("sec-websocket-protocol"):
        if sub.startswith("sentinel."):
            return sub[len("sentinel."):]
    return ""


# --------------------------------------------------------------------------- #
# Frontend static hosting (single-container production deployment)
# Serves the built React app from frontend/dist when it exists. Registered last
# so API/WS routes always take precedence. This lets a single container serve
# both the API and the dashboard.
# --------------------------------------------------------------------------- #
_DIST = WORKSPACE_ROOT / "frontend" / "dist"
if _DIST.is_dir():
    from fastapi.staticfiles import StaticFiles

    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    @app.get("/{full_path:path}", include_in_schema=False)
    def _spa(full_path: str):
        from fastapi.responses import FileResponse, JSONResponse

        if full_path.startswith("api/") or full_path.startswith("ws"):
            return JSONResponse({"detail": "Not found"}, status_code=404)
        candidate = (_DIST / full_path).resolve()
        if not candidate.is_relative_to(_DIST.resolve()):
            return JSONResponse({"detail": "Not found"}, status_code=404)
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_DIST / "index.html")
