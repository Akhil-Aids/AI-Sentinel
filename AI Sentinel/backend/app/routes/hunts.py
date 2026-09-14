"""Threat hunting routes: ad-hoc and saved hunts, CSV export, run history."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from app import db
from app.core.deps import client_ip, current_user, require_privilege_at_least
from app.services.hunts import patterns_list, run_hunt, filters_to_csv

router = APIRouter()


class HuntRunRequest(BaseModel):
    filters: dict = {}
    limit: int = 500


class HuntSaveRequest(BaseModel):
    name: str
    description: str = ""
    query_text: str = ""
    filters: dict = {}


@router.get("/patterns")
def list_patterns(_payload: dict = Depends(current_user)) -> dict:
    return {"items": patterns_list()}


@router.post("/run")
def execute_hunt(body: HuntRunRequest, request: Request,
                 _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    filters = dict(body.filters)
    filters["limit"] = body.limit
    result = run_hunt(filters)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="hunt.run",
                 ip=client_ip(request),
                 detail={"pattern": filters.get("pattern", ""),
                         "group_by": filters.get("group_by"),
                         "result_count": result["count"],
                         "status": result["status"]})
    return result


@router.get("/export")
def export_hunt(
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    host: Optional[str] = None,
    username: Optional[str] = None,
    severity_min: Optional[str] = None,
    group_by: Optional[str] = None,
    min_group_count: int = 1,
    minutes: int = Query(1440, ge=1, le=10080),
    format: str = "csv",
    _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST")),
):
    filters = {"minutes": minutes}
    for key, val in (("event_type", event_type), ("source_ip", source_ip),
                     ("host", host), ("username", username), ("severity_min", severity_min),
                     ("group_by", group_by)):
        if val:
            filters[key] = val
    if group_by:
        filters["min_group_count"] = min_group_count
    csv_text = filters_to_csv(filters)
    return PlainTextResponse(csv_text, media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=hunt.csv"})


@router.get("/")
def list_hunts(_payload: dict = Depends(current_user)) -> dict:
    return {"items": db.list_hunts(), "patterns": patterns_list()}


@router.post("/")
def save_hunt(body: HuntSaveRequest, request: Request,
              _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    hunt = db.save_hunt({
        "name": body.name,
        "description": body.description,
        "query_text": body.query_text,
        "query_filters": body.filters,
        "created_by": _payload["sub"],
    })
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="hunt.save",
                 target=hunt["hunt_id"], ip=client_ip(request), detail={"name": body.name})
    return hunt


@router.get("/{hunt_id}")
def get_hunt(hunt_id: str, _payload: dict = Depends(current_user)) -> dict:
    hunt = db.get_hunt(hunt_id)
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return hunt


@router.put("/{hunt_id}")
def update_hunt(hunt_id: str, body: HuntSaveRequest, request: Request,
                _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    hunt = db.get_hunt(hunt_id)
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")
    db.update_hunt(hunt_id, name=body.name, description=body.description,
                   query_text=body.query_text, query_filters=body.filters)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="hunt.update",
                 target=hunt_id, ip=client_ip(request), detail={"name": body.name})
    return db.get_hunt(hunt_id)


@router.delete("/{hunt_id}")
def delete_hunt(hunt_id: str, request: Request,
                _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    hunt = db.get_hunt(hunt_id)
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")
    db.delete_hunt(hunt_id)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="hunt.delete",
                 target=hunt_id, ip=client_ip(request))
    return {"status": "ok", "hunt_id": hunt_id}


@router.post("/{hunt_id}/run")
def run_saved_hunt(hunt_id: str, request: Request,
                   _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    hunt = db.get_hunt(hunt_id)
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")
    filters = dict(hunt.get("query_filters", {}))
    filters["limit"] = filters.get("limit", 500)
    result = run_hunt(filters)
    db.record_hunt_run(hunt_id, result["count"], result["duration_ms"])
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="hunt.run_saved",
                 target=hunt_id, ip=client_ip(request),
                 detail={"result_count": result["count"], "status": result["status"]})
    return {**result, "hunt": db.get_hunt(hunt_id)}


@router.get("/{hunt_id}/history")
def hunt_history(hunt_id: str, _payload: dict = Depends(current_user)) -> dict:
    hunt = db.get_hunt(hunt_id)
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return {"items": db.list_hunt_runs(hunt_id)}