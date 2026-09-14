"""SOC reporting routes.

Reports are generated on demand from real persisted data and stored with an
audit trail. SOC Analysts may generate and view reports; VIEWER role is
read-only.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app import db, reports
from app.core.deps import current_user, require_privilege_at_least

router = APIRouter()


class ReportRange(BaseModel):
    period_start: Optional[str] = None
    period_end: Optional[str] = None


@router.post("/daily")
def create_daily_report(body: ReportRange,
                        _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    content = reports.build_daily_report(body.period_start, body.period_end)
    rec = db.save_report({
        "report_type": "daily",
        "title": f"Daily SOC Report - {content['period']['label']}",
        "period_start": content["period"]["start"],
        "period_end": content["period"]["end"],
        "summary": content["summary"],
        "content": content,
        "created_by": _payload["sub"],
    })
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="report.daily",
                 result="SUCCESS", target=rec["report_id"],
                 detail={"period_start": content["period"]["start"], "period_end": content["period"]["end"]})
    return rec


@router.post("/posture")
def create_posture_report(_payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    content = reports.build_posture_report()
    rec = db.save_report({
        "report_type": "posture",
        "title": f"Security Posture Report - {content['assessed_at'][:10]}",
        "period_start": content["assessed_at"],
        "period_end": content["assessed_at"],
        "summary": content["summary"],
        "content": content,
        "created_by": _payload["sub"],
    })
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="report.posture",
                 result="SUCCESS", target=rec["report_id"])
    return rec


@router.post("/incident/{incident_id}")
def create_incident_report(incident_id: str,
                           _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    try:
        content = reports.build_incident_report(incident_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Incident not found")
    if isinstance(content["incident"], dict) and content["incident"].get("incident_id"):
        period_start = content["incident"].get("created_at", "")
        period_end = content["incident"].get("resolved_at", "") or content["incident"].get("updated_at", "")
        title = f"Incident Report - {content['incident']['incident_id']}"
    else:
        period_start, period_end, title = "", "", f"Incident Report - {incident_id}"
    rec = db.save_report({
        "report_type": "incident",
        "title": title,
        "period_start": period_start,
        "period_end": period_end,
        "summary": content["summary"],
        "content": content,
        "created_by": _payload["sub"],
    })
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="report.incident",
                 result="SUCCESS", target=incident_id)
    return rec


@router.get("/")
def list_reports(report_type: Optional[str] = Query(None),
                 limit: int = Query(50, ge=1, le=200),
                 _payload: dict = Depends(current_user)) -> dict:
    if report_type and report_type not in ("daily", "posture", "incident"):
        raise HTTPException(status_code=400, detail="report_type must be daily, posture or incident")
    return {"items": db.list_reports(limit=limit, report_type=report_type), "total": len(db.list_reports(limit=limit, report_type=report_type))}


@router.get("/{report_id}")
def get_report(report_id: str, _payload: dict = Depends(current_user)) -> dict:
    rec = db.get_report(report_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Report not found")
    return rec


@router.delete("/{report_id}")
def delete_report(report_id: str,
                  _payload: dict = Depends(require_privilege_at_least("SECURITY_ENGINEER"))) -> dict:
    if not db.get_report(report_id):
        raise HTTPException(status_code=404, detail="Report not found")
    db.delete_report(report_id)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="report.delete",
                 result="SUCCESS", target=report_id)
    return {"status": "ok", "report_id": report_id}