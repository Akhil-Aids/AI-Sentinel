"""Detection rule routes: CRUD, toggle, versioning/rollback, and
test-against-history. Every change is audited and versioned (immutable history).
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app import db
from app.core.deps import client_ip, current_user, require_privilege_at_least
from app.engines.rules import (RULE_CATEGORIES, PREDICATES, default_rules, rule_engine,
                               evaluate_rule_against_history)

router = APIRouter()


class RulePayload(BaseModel):
    rule_id: str = Field(pattern=r"^[a-z0-9_]{3,64}$")
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    category: str = "generic"
    enabled: bool = True
    severity: str = "medium"
    mitre: list[str] = []
    config: dict = {}


class RuleTestRequest(BaseModel):
    minutes: int = Field(60, ge=5, le=10080)
    limit: int = Field(500, ge=1, le=2000)
    event_type: str | None = None


@router.get("/")
def list_rules(_payload: dict = Depends(current_user)) -> dict:
    return {"items": db.list_rules(), "categories": RULE_CATEGORIES,
            "predicates": sorted(PREDICATES.keys())}


@router.post("/")
def create_rule(body: RulePayload, request: Request,
                _payload: dict = Depends(require_privilege_at_least("SECURITY_ENGINEER"))) -> dict:
    if body.rule_id not in PREDICATES:
        raise HTTPException(
            status_code=400,
            detail=f"rule_id must map to a known predicate. Available: {', '.join(sorted(PREDICATES))}",
        )
    if db.get_rule(body.rule_id):
        raise HTTPException(status_code=409, detail="Rule already exists")
    if body.category not in RULE_CATEGORIES:
        raise HTTPException(status_code=400, detail=f"Unknown category. Use one of {', '.join(RULE_CATEGORIES)}")
    if body.severity not in ("info", "low", "medium", "high", "critical"):
        raise HTTPException(status_code=400, detail="Invalid severity")
    rule = db.create_rule({
        "rule_id": body.rule_id,
        "name": body.name,
        "description": body.description,
        "category": body.category,
        "enabled": body.enabled,
        "severity": body.severity,
        "mitre": body.mitre,
        "config": body.config,
    }, changed_by=_payload["sub"])
    rule_engine.rules(refresh=True)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="rule.create",
                 target=body.rule_id, ip=client_ip(request),
                 detail={"category": body.category, "enabled": body.enabled})
    return rule


@router.post("/reset")
def reset_rules(request: Request, _payload: dict = Depends(require_privilege_at_least("ADMIN"))) -> dict:
    count = 0
    for r in default_rules():
        db.upsert_rule(r)
        count += 1
    rule_engine.rules(refresh=True)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="rule.reset",
                 ip=client_ip(request), detail={"restored": count})
    return {"status": "ok", "restored": count}


@router.post("/{rule_id}/toggle")
def toggle_rule(rule_id: str, request: Request,
                _payload: dict = Depends(require_privilege_at_least("SECURITY_ENGINEER"))) -> dict:
    rule = db.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    new_state = not bool(rule["enabled"])
    db.set_rule_enabled(rule_id, new_state)
    rule_engine.rules(refresh=True)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="rule.toggle",
                 target=rule_id, ip=client_ip(request), detail={"enabled": new_state})
    return {"rule_id": rule_id, "enabled": new_state}


@router.put("/{rule_id}")
def update_rule(rule_id: str, body: RulePayload, request: Request,
                _payload: dict = Depends(require_privilege_at_least("SECURITY_ENGINEER"))) -> dict:
    rule = db.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    updated = db.update_rule_with_history(rule_id, {
        "name": body.name,
        "description": body.description,
        "category": body.category,
        "enabled": body.enabled,
        "severity": body.severity,
        "mitre": body.mitre,
        "config": body.config,
    }, changed_by=_payload["sub"])
    rule_engine.rules(refresh=True)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="rule.update",
                 target=rule_id, ip=client_ip(request),
                 detail={"category": body.category, "enabled": body.enabled,
                         "version": updated.get("version")})
    return updated


@router.delete("/{rule_id}")
def delete_rule(rule_id: str, request: Request,
                _payload: dict = Depends(require_privilege_at_least("SECURITY_ENGINEER"))) -> dict:
    rule = db.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete_rule(rule_id)
    rule_engine.rules(refresh=True)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="rule.delete",
                 target=rule_id, ip=client_ip(request),
                 detail={"category": rule["category"], "version": rule.get("version")})
    return {"status": "ok", "rule_id": rule_id}


@router.get("/{rule_id}/history")
def rule_history(rule_id: str, _payload: dict = Depends(current_user)) -> dict:
    rule = db.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"items": db.list_rule_history(rule_id), "current_version": rule.get("version", 1)}


@router.post("/{rule_id}/rollback")
def rollback_rule(rule_id: str, body: dict, request: Request,
                  _payload: dict = Depends(require_privilege_at_least("SECURITY_ENGINEER"))) -> dict:
    rule = db.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    version = int(body.get("version", 0))
    snapshot = db.get_rule_snapshot(rule_id, version) if version > 0 else None
    if snapshot is None:
        raise HTTPException(status_code=404, detail=f"No snapshot for version {version}")
    restored = db.restore_rule_snapshot(rule_id, snapshot.get("snapshot", {}), changed_by=_payload["sub"])
    rule_engine.rules(refresh=True)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="rule.rollback",
                 target=rule_id, ip=client_ip(request),
                 detail={"from_version": version, "to_version": restored.get("version")})
    return restored


@router.post("/{rule_id}/test")
def test_rule(rule_id: str, body: RuleTestRequest, request: Request,
              _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    rule = db.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    result = evaluate_rule_against_history(rule, minutes=body.minutes, limit=body.limit,
                                           event_type=body.event_type)
    db.log_audit(actor=_payload["sub"], role=_payload["role"], action="rule.test",
                 target=rule_id, ip=client_ip(request),
                 detail={"matched": result.get("matched"), "evaluated": result.get("evaluated")})
    return result
