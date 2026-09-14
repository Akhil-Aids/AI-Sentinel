"""Evidence management routes.

Evidence records are immutable after creation (no PATCH). Each record stores a
SHA-256 content digest; the integrity status is derived by re-hashing the stored
content, so tampering is detected, never assumed.
"""
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app import db
from app.core.deps import client_ip, require_privilege_at_least

router = APIRouter()

EVIDENCE_TYPES = ("log", "packet", "file", "process", "url", "domain", "ip", "memory",
                  "registry", "artifact", "screenshot", "other")


class EvidenceCreateRequest(BaseModel):
    type: str = "artifact"
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    source: str = ""
    content: str = ""
    content_hash: str = ""
    incident_id: str = ""
    alert_id: str = ""
    case_id: str = ""
    event_ids: list[str] = []
    metadata: dict = {}


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _decide_integrity(content: str, provided_hash: str) -> tuple[str, str]:
    """Return (content_hash, integrity_status)."""
    if provided_hash and content:
        return provided_hash, "PENDING"
    if content:
        return _digest(content), "VERIFIED"
    if provided_hash:
        return provided_hash, "NOT_APPLICABLE"
    return "", "NOT_APPLICABLE"


@router.post("/")
def create_evidence(body: EvidenceCreateRequest, request: Request,
                    payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    if body.type not in EVIDENCE_TYPES:
        raise HTTPException(status_code=400, detail=f"Type must be one of {', '.join(EVIDENCE_TYPES)}")
    refs = bool(body.incident_id or body.alert_id or body.case_id)
    if not refs:
        raise HTTPException(status_code=400, detail="Attach evidence to an incident, alert or case")
    if body.incident_id and not db.get_incident(body.incident_id):
        raise HTTPException(status_code=404, detail="Incident not found")
    if body.alert_id and not db.get_alert(body.alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    if body.case_id and not db.get_case(body.case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    content_hash, integrity = _decide_integrity(body.content, body.content_hash)
    evidence = db.create_evidence(
        evidence_id=db.new_id("ev"), incident_id=body.incident_id, alert_id=body.alert_id,
        case_id=body.case_id, event_ids=body.event_ids, etype=body.type, title=body.title,
        description=body.description, source=body.source, content_raw=body.content,
        content_hash=content_hash, integrity_status=integrity, created_by=payload["sub"],
        metadata=body.metadata,
    )
    db.log_audit(actor=payload["sub"], role=payload["role"], action="evidence.create",
                 target=evidence["evidence_id"], ip=client_ip(request),
                 detail={"type": body.type, "integrity_status": integrity, "incident_id": body.incident_id})
    return evidence


@router.get("/")
def list_evidence(incident_id: str | None = None, case_id: str | None = None,
                  alert_id: str | None = None, limit: int = 100,
                  _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    return {"items": db.list_evidence(incident_id=incident_id, case_id=case_id,
                                      alert_id=alert_id, limit=limit)}


@router.get("/{evidence_id}")
def get_evidence(evidence_id: str,
                 _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    evidence = db.get_evidence(evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence


@router.post("/{evidence_id}/verify")
def verify_evidence(evidence_id: str, request: Request,
                    payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    evidence = db.get_evidence(evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    status = "NOT_APPLICABLE"
    if evidence.get("content_raw"):
        status = "VERIFIED" if _digest(evidence["content_raw"]) == evidence.get("content_hash") else "TAMPERED"
    db.update_evidence_integrity(evidence_id, status)
    db.log_audit(actor=payload["sub"], role=payload["role"], action="evidence.verify",
                 target=evidence_id, ip=client_ip(request), detail={"integrity_status": status})
    return {"evidence_id": evidence_id, "integrity_status": status}


@router.delete("/{evidence_id}")
def delete_evidence(evidence_id: str, request: Request,
                    payload: dict = Depends(require_privilege_at_least("SECURITY_ENGINEER"))) -> dict:
    if not db.get_evidence(evidence_id):
        raise HTTPException(status_code=404, detail="Evidence not found")
    db.delete_evidence(evidence_id)
    db.log_audit(actor=payload["sub"], role=payload["role"], action="evidence.delete",
                 target=evidence_id, ip=client_ip(request))
    return {"status": "ok"}