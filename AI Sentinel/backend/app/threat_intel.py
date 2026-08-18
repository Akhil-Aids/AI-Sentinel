"""Threat intelligence layer.

Local indicator store (seeded from a local JSON/YAML file and analyst-added
IOCs) plus optional remote providers (AbuseIPDB, VirusTotal). Remote lookups
happen in a worker with short timeouts; results are cached in the database so
the hot detection path never depends on external network availability.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

from app import db
from app.core.config import settings

LOCAL_IOC_FILE = Path(__file__).resolve().parents[1] / "data" / "local_iocs.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_local_iocs() -> dict:
    """Return {ioc_type: {value: verdict}} from the local indicators file."""
    if not LOCAL_IOC_FILE.exists():
        return {}
    try:
        data = json.loads(LOCAL_IOC_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data.get("indicators", {})


def seed_local_iocs() -> int:
    loaded = 0
    for ioc_type, items in load_local_iocs().items():
        for value, verdict in items.items():
            existing = db.get_ti(ioc_type, value)
            if existing is None:
                db.upsert_ti(ioc_type, value, source="local", verdict=verdict)
                loaded += 1
    return loaded


def check_local(ioc_type: str, value: str) -> Optional[dict]:
    return db.get_ti(ioc_type, value)


# --------------------------------------------------------------------------- #
# Remote providers (optional). Fail-safe: any error returns None.
# --------------------------------------------------------------------------- #
def check_abuseipdb(ip: str) -> Optional[dict]:
    key = settings.TI_ABUSEIPDB_KEY
    if not key:
        return None
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": key, "Accept": "application/json"},
            timeout=4,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "source": "abuseipdb",
            "verdict": "malicious" if data.get("abuseConfidenceScore", 0) >= 50 else "clean",
            "score": data.get("abuseConfidenceScore", 0),
            "detail": f"abuseConfidenceScore={data.get('abuseConfidenceScore', 0)}",
        }
    except Exception:
        return None


def check_virustotal(ioc_type: str, value: str) -> Optional[dict]:
    key = settings.TI_VT_API_KEY
    if not key:
        return None
    url = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{value}",
        "url": f"https://www.virustotal.com/api/v3/urls/{value}",
        "file": f"https://www.virustotal.com/api/v3/files/{value}",
    }.get(ioc_type)
    if not url:
        return None
    try:
        resp = requests.get(url, headers={"x-apikey": key}, timeout=4)
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        return {
            "source": "virustotal",
            "verdict": "malicious" if malicious > 0 else "clean",
            "score": min(100, malicious * 10),
            "detail": f"last_analysis_stats={json.dumps(stats)}",
        }
    except Exception:
        return None


def lookup(ioc_type: str, value: str) -> dict:
    """Check local store first, then remote (if enabled). Caches results."""
    local = check_local(ioc_type, value)
    if local:
        local["cached"] = True
        return local

    result = None
    if settings.TI_ENABLED:
        if ioc_type == "ip":
            result = check_abuseipdb(value)
        if result is None:
            result = check_virustotal(ioc_type, value)

    if result:
        db.upsert_ti(ioc_type, value, source=result["source"], verdict=result["verdict"])
        result["cached"] = False
        return result

    return {"source": "none", "verdict": "unknown", "score": 0, "cached": True}


def ti_bonus(ioc_type: str, value: str) -> float:
    """Risk bonus (0-100) for a known-malicious indicator."""
    if not value:
        return 0.0
    entry = check_local(ioc_type, value)
    if entry and entry["verdict"] == "malicious":
        return 50.0
    return 0.0
