import os
import sys
import tempfile
from pathlib import Path

# Must be set before any `app.*` import so settings/db bind to a temp store.
_TMP = tempfile.mkdtemp(prefix="sentinel_test_")
os.environ["SENTINEL_ENV"] = "test"
os.environ["SENTINEL_DB_PATH"] = str(Path(_TMP) / "test.db")
os.environ["SENTINEL_MODEL_DIR"] = str(Path(_TMP) / "models")
os.environ["SENTINEL_ADMIN_PASSWORD"] = "test-admin-pass-123"
os.environ["SENTINEL_ML_ENABLED"] = "false"
os.environ["SENTINEL_TI_ENABLED"] = "false"
os.environ["SENTINEL_RESPONSE_DRY_RUN"] = "true"
os.environ["SENTINEL_DEMO_MODE"] = "false"
os.environ["SENTINEL_AGENT_KEY"] = "test-agent-key-123"

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

TEST_PASSWORD = os.environ["SENTINEL_ADMIN_PASSWORD"]
TEST_USERNAME = "admin"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin_token(client):
    res = client.post("/api/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})
    assert res.status_code == 200, res.text
    return res.json()["token"]


@pytest.fixture(scope="module")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(autouse=True)
def _clear_login_rate_limiter():
    """The login rate limiter is in-memory and keyed by client IP; the TestClient
    always presents the same IP, so reset the window between tests to avoid
    cross-test 429s while keeping the limiter fully exercised within a test."""
    from app.routes import auth as _auth
    _auth._LOGIN_WINDOWS.clear()
    yield
    _auth._LOGIN_WINDOWS.clear()
