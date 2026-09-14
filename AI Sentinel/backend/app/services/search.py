"""Global search across stored security entities.

Groups results by entity type (events, alerts, incidents, hosts, iocs, users).
All columns are fixed SQL-side; the query text is always a bound parameter.
Empty or very short queries return an explicit NO_QUERY result rather than a
pointless full-table scan.
"""
from app import db

MIN_QUERY_LEN = 2
DEFAULT_LIMIT = 5


def _search(table: str, columns: list[str], q: str, limit: int) -> list[dict]:
    like = f"%{q}%"
    clauses = [f"{col} LIKE ?" for col in columns]
    return db._fetch_all(
        f"SELECT * FROM {table} WHERE ({' OR '.join(clauses)}) ORDER BY rowid DESC LIMIT ?",
        tuple([like] * len(columns) + [limit]),
    )


def search_all(q: str, limit: int = DEFAULT_LIMIT) -> dict:
    q = (q or "").strip()
    if len(q) < MIN_QUERY_LEN:
        return {"query": q, "status": "NO_QUERY",
                "message": "Query must be at least 2 characters.", "groups": {}}

    groups = {
        "events": _search("events",
                          ["event_id", "event_type", "source_ip", "dest_ip", "host",
                           "username", "target", "process", "command", "source"],
                          q, limit),
        "alerts": _search("alerts", ["alert_id", "title", "description", "source"], q, limit),
        "incidents": _search("incidents",
                             ["incident_id", "title", "affected_host", "affected_user",
                              "source_ip", "category"], q, limit),
        "hosts": _search("servers", ["hostname", "ip"], q, limit),
        "iocs": _search("iocs", ["ioc_id", "ioc_value", "ioc_type", "source", "threat_actor"],
                        q, limit),
        "users": _search("users", ["username", "full_name", "role"], q, limit),
    }

    # Slim fields for large event rows.
    for ev in groups["events"]:
        for key in ("raw", "details", "timeline", "event_ids", "mitre"):
            ev.pop(key, None)

    total = sum(len(v) for v in groups.values())
    return {"query": q, "status": "OK", "groups": groups, "total": total,
            "limit_per_group": limit}