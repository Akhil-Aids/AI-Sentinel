"""AI Sentinel API entrypoint."""
import asyncio
import secrets
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import db
from app.core.config import WORKSPACE_ROOT, settings, validate_settings
from app.core.logging import RequestFilter, setup_logging
from app.core.security import hash_password, decode_token
from app.pipeline import pipeline
from app.services.ws_manager import ws_manager
from app.telemetry.collector import run_collector_loop

@asynccontextmanager
async def lifespan(app):
    setup_logging(level="DEBUG" if settings.DEBUG else "INFO")
    validate_settings()
    db.init_schema()
    bootstrap_admin()
    pipeline.start()
    asyncio.create_task(run_collector_loop())
    asyncio.create_task(_retention_loop())
    asyncio.create_task(_ml_retrain_loop())
    asyncio.create_task(_metric_history_loop())
    if settings.DEMO_MODE:
        from app.telemetry.demo import run_demo_loop
        asyncio.create_task(run_demo_loop())
    print(f"{settings.APP_NAME} v{settings.APP_VERSION} started "
          f"(env={settings.ENV}, storage={settings.DB_PATH}, demo_mode={settings.DEMO_MODE})")
    yield
    try:
        await pipeline.stop()
    except Exception:
        pass


app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RequestIDMiddleware:
    """Pure ASGI middleware — no BaseHTTPMiddleware (avoids blocking the event loop)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        rid = ""
        for name, value in scope.get("headers", []):
            if name == b"x-request-id":
                rid = value.decode("latin-1")
                break
        if not rid:
            rid = uuid.uuid4().hex[:12]
        RequestFilter.set_context(request_id=rid)
        scope.setdefault("state", {})["request_id"] = rid

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", rid.encode("latin-1")))
                message["headers"] = headers
            return await send(message)

        try:
            return await self.app(scope, receive, send_wrapper)
        finally:
            RequestFilter.clear_context()


app.add_middleware(RequestIDMiddleware)


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


async def _metric_history_loop() -> None:
    """Persist SOC KPIs into metric_history on a schedule for trend analysis."""
    from app.services.metrics import soc_metrics
    while True:
        await asyncio.sleep(settings.METRIC_HISTORY_INTERVAL)
        try:
            if not settings.METRIC_HISTORY_ENABLED:
                continue
            metrics = soc_metrics(days=7)
            for key in ("mttd", "mtta", "mttr_respond", "mttr_resolve"):
                entry = metrics[key]
                db.record_metric(entry["metric"], round(float(entry["minutes"] or 0), 2),
                                 {"label": entry["label"], "samples": entry.get("samples", 0)})
        except Exception as exc:
            db.log_audit(actor="system", action="metric_history.sample", result="FAILED",
                         detail={"error": str(exc)})




# --------------------------------------------------------------------------- #
# Routers
# --------------------------------------------------------------------------- #
from app.routes.auth import router as auth_router  # noqa: E402
from app.routes.api_keys import router as api_keys_router  # noqa: E402
from app.routes.cases import router as cases_router  # noqa: E402
from app.routes.evidence import router as evidence_router  # noqa: E402
from app.routes.tasks import router as tasks_router  # noqa: E402
from app.routes.sla import router as sla_router  # noqa: E402
from app.routes.mitre_center import router as mitre_router  # noqa: E402
from app.routes.posture import router as posture_router  # noqa: E402
from app.routes.data_quality import router as data_quality_router  # noqa: E402
from app.routes.alerts import router as alerts_router  # noqa: E402
from app.routes.approvals import router as approvals_router  # noqa: E402
from app.routes.agents import router as agents_router  # noqa: E402
from app.routes.chatbot import router as chatbot_router  # noqa: E402
from app.routes.events import router as events_router  # noqa: E402
from app.routes.health import router as health_router  # noqa: E402
from app.routes.hosts import router as hosts_router  # noqa: E402
from app.routes.hunts import router as hunts_router  # noqa: E402
from app.routes.incidents import router as incidents_router  # noqa: E402
from app.routes.iocs import router as iocs_router  # noqa: E402
from app.routes.ml_routes import router as ml_router  # noqa: E402
from app.routes.network import router as network_router  # noqa: E402
from app.routes.notifications import router as notifications_router  # noqa: E402
from app.routes.overview import router as overview_router  # noqa: E402
from app.routes.phishing import router as phishing_router  # noqa: E402
from app.routes.reports import router as reports_router  # noqa: E402
from app.routes.risks import router as risks_router  # noqa: E402
from app.routes.respond import router as respond_router  # noqa: E402
from app.routes.rules import router as rules_router  # noqa: E402
from app.routes.search import router as search_router  # noqa: E402

app.include_router(auth_router, prefix="/api/auth", tags=["Auth"])
app.include_router(api_keys_router, prefix="/api/system", tags=["API Keys"])
app.include_router(cases_router, prefix="/api/cases", tags=["Cases"])
app.include_router(evidence_router, prefix="/api/evidence", tags=["Evidence"])
app.include_router(tasks_router, prefix="/api/tasks", tags=["Tasks"])
app.include_router(sla_router, prefix="/api/sla", tags=["SLA"])
app.include_router(mitre_router, prefix="/api/mitre", tags=["MITRE Center"])
app.include_router(posture_router, prefix="/api/posture", tags=["Posture"])
app.include_router(data_quality_router, prefix="/api/data-quality", tags=["Data quality"])
app.include_router(overview_router, prefix="/api", tags=["Overview"])
app.include_router(events_router, prefix="/api/events", tags=["Events"])
app.include_router(incidents_router, prefix="/api/incidents", tags=["Incidents"])
app.include_router(iocs_router, prefix="/api/iocs", tags=["IOCs"])
app.include_router(alerts_router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(approvals_router, prefix="/api/approvals", tags=["Approvals"])
app.include_router(hosts_router, prefix="/api/hosts", tags=["Hosts"])
app.include_router(hunts_router, prefix="/api/hunts", tags=["Threat Hunting"])
app.include_router(network_router, prefix="/api/network", tags=["Network"])
app.include_router(rules_router, prefix="/api/rules", tags=["Rules"])
app.include_router(search_router, prefix="/api/search", tags=["Search"])
app.include_router(phishing_router, prefix="/api/phishing", tags=["Phishing"])
app.include_router(chatbot_router, prefix="/api/chatbot", tags=["Chatbot"])
app.include_router(health_router, prefix="/api/system", tags=["System"])
app.include_router(agents_router, prefix="/api/agents", tags=["Agents"])
app.include_router(respond_router, prefix="/api/respond", tags=["Response"])
app.include_router(ml_router, prefix="/api/ml", tags=["ML"])
app.include_router(reports_router, prefix="/api/reports", tags=["Reports"])
app.include_router(risks_router, prefix="/api/risks", tags=["Risk Insights"])
app.include_router(notifications_router, prefix="/api/notifications", tags=["Notifications"])


# --------------------------------------------------------------------------- #
# Structured error responses (ISO 8601 + request_id correlation)
# --------------------------------------------------------------------------- #
def _error_body(request: Request, exc_detail) -> dict:
    """Structured error envelope — keeps the legacy `detail` key intact for
    existing consumers while adding request_id + timestamp correlation."""
    from datetime import datetime, timezone
    return {
        "detail": exc_detail,
        "request_id": getattr(request.state, "request_id", None) or "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_body(request, exc.detail),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=_error_body(request, exc.errors()),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Re-raise non-API errors so static/websocket paths keep their default handling.
    path = request.url.path
    if not path.startswith("/api/"):
        raise exc
    db.log_audit(actor="system", action="http.unhandled_error", result="FAILED",
                 detail={"path": path, "error": type(exc).__name__})
    request_id = getattr(request.state, "request_id", None) or ""
    from datetime import datetime, timezone
    return JSONResponse(
        status_code=500,
        content={
            "detail": f"Internal server error ({type(exc).__name__})",
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


# --------------------------------------------------------------------------- #
# Public health (no auth)
# --------------------------------------------------------------------------- #
@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "ai-sentinel", "version": settings.APP_VERSION,
            "demo_mode": settings.DEMO_MODE}


@app.get("/api/ready")
def ready():
    """Readiness probe (no auth) for orchestrators/load balancers.

    200 = ready to serve traffic (DB reachable, pipeline running). 503 = not ready.
    """
    import sqlite3

    checks: dict[str, str] = {}
    db_ok = True
    try:
        db.get_connection().execute("SELECT 1").fetchone()
        checks["database"] = "ok"
    except sqlite3.Error:
        checks["database"] = "error"
        db_ok = False
    checks["pipeline"] = "ok" if pipeline._started else "starting"
    pipeline_ok = pipeline._started
    ready_ok = db_ok and pipeline_ok
    return JSONResponse(
        {"status": "ready" if ready_ok else "not_ready", "checks": checks},
        status_code=200 if ready_ok else 503,
    )


# --------------------------------------------------------------------------- #
# Authenticated WebSocket event stream
# --------------------------------------------------------------------------- #
@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    """Authenticated live event stream.

    Token MUST be supplied as a Sec-WebSocket-Protocol subprotocol header
    (`sentinel.<token>`). Tokens in URL query parameters are NOT accepted
    because URLs can be logged by proxies, browsers, and monitoring systems.
    """
    auth_token = _token_from_subprotocol(websocket)
    if not auth_token:
        await websocket.close(code=4401)
        return
    try:
        identity = decode_token(auth_token)
    except Exception:
        await websocket.close(code=4401)
        return
    # Enforce same checks as REST auth: user exists, is active, not revoked
    from app.core.deps import _revoked_tokens, _user_is_active
    raw_token = auth_token
    if raw_token in _revoked_tokens:
        await websocket.close(code=4401)
        return
    if not _user_is_active(identity.get("sub", "")):
        await websocket.close(code=4403)
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
    for sub in websocket.headers.getlist("sec-websocket-protocol"):
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
