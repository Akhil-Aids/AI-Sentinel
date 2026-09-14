"""MITRE ATT&CK coverage center, detection gaps and post-incident review."""
from fastapi import APIRouter, Depends, HTTPException, Request

from app import db
from app.core.deps import client_ip, require_privilege_at_least
from app.services import mitre_center

router = APIRouter()


@router.get("/coverage/")
def coverage(_payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    return mitre_center.coverage()


@router.post("/incidents/{incident_id}/review")
def incident_review(incident_id: str, request: Request,
                    payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    inc = db.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    review = mitre_center.produce_review(inc)
    db.add_incident_history(incident_id, "review", "", "COMPLETE",
                            actor=payload["sub"], note=f"Post-incident review recorded ({len(review.get('recommendations', []))} recommendation(s))")
    db.log_audit(actor=payload["sub"], role=payload["role"], action="incident.review",
                 target=incident_id, ip=client_ip(request),
                 detail={"findings": len(review.get("findings", [])),
                         "recommendations": len(review.get("recommendations", []))})
    return review