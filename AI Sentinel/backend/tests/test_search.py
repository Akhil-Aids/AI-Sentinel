"""Tests for the global search endpoint and service."""
import pytest

from app import db
from app.pipeline.normalize import normalize_raw
from app.services.search import search_all


@pytest.fixture(scope="module")
def seeded_search_data():
    db.save_event(normalize_raw({
        "event_type": "auth.failed_login", "source_ip": "203.0.113.51",
        "username": "search_probe_user", "host": "search-host-01",
    }, source="search-test"))
    db.save_ioc({"ioc_type": "ip", "ioc_value": "203.0.113.52", "verdict": "malicious",
                 "confidence": 0.9, "source": "feed", "tags": ["apt"]})
    yield
    db._execute("DELETE FROM events WHERE source = 'search-test'")
    db._execute("DELETE FROM iocs WHERE ioc_value = '203.0.113.52'")


def test_search_service_grouped(seeded_search_data):
    result = search_all("search-host-01")
    assert result["status"] == "OK"
    assert any(e["host"] == "search-host-01" for e in result["groups"]["events"])


def test_search_finds_ioc(seeded_search_data):
    result = search_all("203.0.113.52")
    assert result["status"] == "OK"
    assert any(i["ioc_value"] == "203.0.113.52" for i in result["groups"]["iocs"])


def test_search_short_query_rejected(seeded_search_data):
    result = search_all("a")
    assert result["status"] == "NO_QUERY"


def test_search_no_matches(seeded_search_data):
    result = search_all("zzzz-no-such-entity-zzzz")
    assert result["status"] == "OK"
    assert result["total"] == 0


def test_search_api(client, admin_headers, seeded_search_data):
    r = client.get("/api/search/?q=search-host-01", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "OK"
    assert "events" in body["groups"]

    # Requires auth
    r = client.get("/api/search/?q=anything")
    assert r.status_code in (401, 403)