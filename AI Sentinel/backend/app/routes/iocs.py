"""IOC management routes: CRUD, bulk import/export (CSV/JSON), and match records."""
import csv
import io
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app import db
from app.core.deps import client_ip, current_user, require_privilege_at_least
from app.services.ioc import IOC_TYPES, VALID_VERDICTS, VALID_TLPS, ioc_service

router = APIRouter()

CSV_HEADERS = ("ioc_type", "ioc_value", "verdict", "confidence", "source",
               "tags", "tlp", "threat_actor", "kill_chain_phase")


class IOCPayload(BaseModel):
    ioc_type: str
    ioc_value: str
    verdict: str = "unknown"
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    source: str = "manual"
    tags: list[str] = []
    tlp: str = "WHITE"
    threat_actor: str = ""
    kill_chain_phase: str = ""


class IOCImportPayload(BaseModel):
    items: list[IOCPayload]
    mode: str = "merge"  # merge | replace (replace clears existing IOCs first)


@router.get("/")
def list_iocs(
    ioc_type: Optional[str] = Query(None, description="Filter by indicator type"),
    verdict: Optional[str] = Query(None, description="Filter by verdict"),
    limit: int = Query(200, ge=1, le=1000),
    _payload: dict = Depends(current_user),
) -> dict:
    items = db.list_iocs(limit=limit, ioc_type=ioc_type, verdict=verdict)
    enriched = []
    for ioc in items:
        matches = db.ioc_match_counts(ioc["ioc_id"])
        ioc["match_count"] = matches["count"]
        ioc["last_match_at"] = matches["last_match_at"]
        enriched.append(ioc)
    return {"items": enriched, "count": len(enriched),
            "ioc_types": list(IOC_TYPES), "verdicts": list(VALID_VERDICTS)}


@router.get("/export")
def export_iocs(
    ioc_type: Optional[str] = None,
    verdict: Optional[str] = None,
    format: str = "json",
    _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST")),
):
    rows = ioc_service.export_iocs(ioc_type=ioc_type, verdict=verdict)
    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(CSV_HEADERS)
        for r in rows:
            writer.writerow([r.get("ioc_type", ""), r.get("ioc_value", ""), r.get("verdict", ""),
                             r.get("confidence", 0.0), r.get("source", ""),
                             ";".join(r.get("tags", [])), r.get("tlp", "WHITE"),
                             r.get("threat_actor", ""), r.get("kill_chain_phase", "")])
        return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                                 headers={"Content-Disposition": "attachment; filename=iocs.csv"})
    return {"items": rows}


@router.post("/")
def create_ioc(body: IOCPayload, request: Request,
               _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    if body.ioc_type not in IOC_TYPES:
        raise HTTPException(status_code=400, detail=f"ioc_type must be one of {', '.join(IOC_TYPES)}")
    if body.verdict not in VALID_VERDICTS:
        raise HTTPException(status_code=400, detail=f"verdict must be one of {', '.join(VALID_VERDICTS)}")
    if body.tlp.upper() not in VALID_TLPS:
        raise HTTPException(status_code=400, detail=f"tlp must be one of {', '.join(VALID_TLPS)}")
    result = ioc_service.import_iocs([body.model_dump()], actor=_payload["sub"])
    ioc = db.get_ioc_by_value(body.ioc_type.lower().strip(), body.ioc_value.strip())
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="ioc.create",
                 target=ioc["ioc_id"] if ioc else "", ip=client_ip(request),
                 detail={"ioc_type": body.ioc_type, "ioc_value": body.ioc_value,
                         "verdict": body.verdict, "inserted": result["inserted"]})
    return ioc


@router.post("/import")
def import_iocs(body: IOCImportPayload, request: Request,
                _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    if body.mode == "replace":
        existing = db.list_iocs(limit=100000)
        for ioc in existing:
            db.delete_ioc(ioc["ioc_id"])
    result = ioc_service.import_iocs([i.model_dump() for i in body.items], actor=_payload["sub"])
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="ioc.import",
                 ip=client_ip(request), detail={"mode": body.mode, "rows": len(body.items),
                                                "inserted": result["inserted"],
                                                "updated": result["updated"],
                                                "rejected": result["rejected"]})
    return {k: v for k, v in result.items() if k != "rejected_rows"}


@router.get("/{ioc_id}")
def get_ioc(ioc_id: str, _payload: dict = Depends(current_user)) -> dict:
    ioc = db.get_ioc(ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    match_rows = db._fetch_all(
        "SELECT event_id, matched_at, context FROM ioc_matches WHERE ioc_id = ? ORDER BY matched_at DESC LIMIT 50",
        (ioc_id,),
    )
    ioc["match_records"] = match_rows
    ioc["match_count"] = len(match_rows)
    return ioc


@router.put("/{ioc_id}")
def update_ioc(ioc_id: str, body: IOCPayload, request: Request,
               _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    ioc = db.get_ioc(ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    if body.ioc_type not in IOC_TYPES:
        raise HTTPException(status_code=400, detail=f"ioc_type must be one of {', '.join(IOC_TYPES)}")
    if body.verdict not in VALID_VERDICTS:
        raise HTTPException(status_code=400, detail=f"verdict must be one of {', '.join(VALID_VERDICTS)}")
    db.update_ioc(ioc_id,
                  verdict=body.verdict,
                  confidence=body.confidence,
                  source=body.source,
                  tags=body.tags,
                  tlp=body.tlp.upper(),
                  threat_actor=body.threat_actor,
                  kill_chain_phase=body.kill_chain_phase)
    ioc_service._refresh_cache(force=True)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="ioc.update",
                 target=ioc_id, ip=client_ip(request),
                 detail={"verdict": body.verdict, "confidence": body.confidence})
    return db.get_ioc(ioc_id)


@router.delete("/{ioc_id}")
def delete_ioc(ioc_id: str, request: Request,
               _payload: dict = Depends(require_privilege_at_least("ADMIN"))) -> dict:
    ioc = db.get_ioc(ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    db.delete_ioc(ioc_id)
    ioc_service._refresh_cache(force=True)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="ioc.delete",
                 target=ioc_id, ip=client_ip(request),
                 detail={"ioc_type": ioc.get("ioc_type"), "ioc_value": ioc.get("ioc_value")})
    return {"status": "ok", "ioc_id": ioc_id}


@router.get("/{ioc_id}/matches")
def ioc_matches(ioc_id: str, limit: int = Query(100, ge=1, le=500),
                _payload: dict = Depends(current_user)) -> dict:
    ioc = db.get_ioc(ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    rows = db.list_ioc_matches(limit=limit)
    rows = [r for r in rows if r["ioc_id"] == ioc_id]
    events = {}
    for r in rows:
        ev = db.get_event_by_id(r["event_id"])
        if ev:
            events[r["event_id"]] = {
                "event_id": ev.get("event_id"), "ts": ev.get("ts"),
                "event_type": ev.get("event_type"), "severity": ev.get("severity"),
                "host": ev.get("host"), "username": ev.get("username"),
                "source_ip": ev.get("source_ip"), "is_simulated": ev.get("is_simulated"),
            }
    return {"items": rows, "events": events}