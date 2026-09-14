"""Controlled response engine.

Every automated action requires a policy, reason, actor, timestamp, audit
record and result status. Destructive actions are gated behind
SENTINEL_RESPONSE_DRY_RUN (enabled by default) so nothing destructive runs
unless explicitly configured by an administrator.

Destructive actions against high-severity incidents additionally require an
explicit manager approval: the engine returns `PENDING_APPROVAL` with an
approval_id, and the action only dispatches after POST /api/approvals/{id}/approve.
"""
from datetime import datetime, timezone

from app import db
from app.core.config import settings

# Policy-gated actions. Each maps to what the engine is permitted to do.
POLICIES = {
    "ALERT_SOC": {"permitted": True},
    "ISOLATE_ENDPOINT": {"permitted": not settings.RESPONSE_DRY_RUN, "destructive": True},
    "REVOKE_SESSIONS": {"permitted": not settings.RESPONSE_DRY_RUN, "destructive": True},
    "BLOCK_IP": {"permitted": not settings.RESPONSE_DRY_RUN, "destructive": True},
    "QUARANTINE_FILE": {"permitted": not settings.RESPONSE_DRY_RUN, "destructive": True},
    "REQUIRE_MFA": {"permitted": not settings.RESPONSE_DRY_RUN},
    "PROTECT_BACKUPS": {"permitted": True},
    "PRESERVE_EVIDENCE": {"permitted": True},
}

ACTION_LABELS = {
    "ALERT_SOC": "Notify SOC team",
    "ISOLATE_ENDPOINT": "Isolate affected endpoint",
    "REVOKE_SESSIONS": "Revoke suspicious sessions",
    "BLOCK_IP": "Block suspicious source",
    "QUARANTINE_FILE": "Quarantine suspicious file",
    "REQUIRE_MFA": "Require additional authentication",
    "PROTECT_BACKUPS": "Protect/verify backups",
    "PRESERVE_EVIDENCE": "Preserve evidence",
}

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class ResponseEngine:
    def policy_status(self, action: str) -> dict:
        policy = POLICIES.get(action)
        if not policy:
            return {"action": action, "permitted": False, "reason": "Unknown action", "dry_run": True}
        return {
            "action": action,
            "permitted": policy["permitted"],
            "destructive": policy.get("destructive", False),
            "dry_run": settings.RESPONSE_DRY_RUN,
            "reason": "Policy permits" if policy["permitted"] else "Blocked: dry-run mode (set SENTINEL_RESPONSE_DRY_RUN=false to enable)",
        }

    def requires_approval(self, action: str, incident_id: str) -> bool:
        policy = POLICIES.get(action, {})
        if not policy.get("destructive"):
            return False
        severity = "medium"
        if incident_id:
            inc = db.get_incident(incident_id)
            if inc:
                severity = inc.get("severity", "medium")
        min_sev = settings.APPROVAL_REQUIRED_MIN_SEVERITY or "high"
        return SEVERITY_RANK.get(severity, 1) >= SEVERITY_RANK.get(min_sev, 2)

    def execute(self, action: str, incident_id: str, reason: str, actor: str,
                policy: str = "", approval: dict | None = None) -> dict:
        status = self.policy_status(action)
        rollback = ""
        if action == "ISOLATE_ENDPOINT":
            rollback = "Re-enable network access for the endpoint after investigation."
        elif action == "REVOKE_SESSIONS":
            rollback = "Re-issue sessions after MFA validation."
        elif action == "BLOCK_IP":
            rollback = "Remove the firewall rule after source is cleared."

        # Approval gate: destructive action on a high-severity incident that has
        # not yet been approved -> record a PENDING approval and stop.
        if not approval and self.requires_approval(action, incident_id):
            req = db.create_approval({
                "action_type": action,
                "action_params": {"incident_id": incident_id, "reason": reason,
                                  "policy": policy or action},
                "incident_id": incident_id,
                "requested_by": actor,
                "status": "PENDING",
                "reason": reason,
            })
            result = "PENDING_APPROVAL"
            detail = {
                "action": action,
                "incident_id": incident_id,
                "reason": reason,
                "requested_by": actor,
                "note": (f"Destructive action requires manager approval "
                         f"({settings.APPROVAL_REQUIRED_MIN_SEVERITY} severity threshold)."),
                "approval_id": req["approval_id"],
                "approved_by": "REQUIRED",
            }
            saved = db.save_response_action({
                "incident_id": incident_id,
                "policy": policy or action,
                "action": action,
                "reason": reason,
                "actor": actor,
                "result": result,
                "detail": detail,
                "rollback": rollback,
            })
            saved["detail"] = detail
            db.log_audit(
                actor=actor,
                role=actor.split("(")[-1].rstrip(")") if "(" in actor else "",
                action=f"response.{action.lower()}",
                result=result,
                target=incident_id or "",
                detail={"incident_id": incident_id, "action": action,
                        "approval_id": req["approval_id"], "approved_by": "REQUIRED"},
            )
            return {"recorded": saved, "status": status, "result": result,
                    "approval_id": req["approval_id"], "blocked": "PENDING_APPROVAL",
                    "reason": detail["note"]}

        if not status["permitted"]:
            result = "BLOCKED"
            detail = {"reason": status["reason"], "action": action, "error": status["reason"]}
        elif status["dry_run"]:
            # Non-destructive actions execute; destructive ones are recorded only.
            result = "DRY_RUN" if status.get("destructive") else "SUCCESS"
            detail = {"executed": not status.get("destructive"), "action": action,
                      "note": "dry-run policy"}
        else:
            result = "SUCCESS"
            detail = {"executed": True, "action": action,
                      "note": "action dispatched to integration (integration adapter required for real enforcement)"}

        detail.update({
            "incident_id": incident_id,
            "policy_id": policy or action,
            "requested_by": actor,
            "approved_by": actor if not (status.get("destructive") and status["permitted"]) else "REQUIRED",
            "executed_at": datetime.now(timezone.utc).isoformat() if result == "SUCCESS" else None,
        })
        if approval:
            detail["approval_id"] = approval.get("approval_id", "")
            detail["approved_by"] = approval.get("approved_by", actor)

        saved = db.save_response_action({
            "incident_id": incident_id,
            "policy": policy or action,
            "action": action,
            "reason": reason,
            "actor": actor,
            "result": result,
            "detail": detail,
            "rollback": rollback,
        })
        saved["detail"] = detail
        saved["detail"]["action_id"] = saved.get("action_id")

        db.log_audit(
            actor=actor,
            role=actor.split("(")[-1].rstrip(")") if "(" in actor else "",
            action=f"response.{action.lower()}",
            result=result,
            target=incident_id or "",
            detail={"incident_id": incident_id, "reason": reason, "action_id": saved.get("action_id"),
                    "permitted": status["permitted"], "dry_run": status["dry_run"]},
        )

        if incident_id:
            actions_taken = []
            inc = db.get_incident(incident_id)
            if inc:
                actions_taken = list(inc.get("actions_taken", []))
            actions_taken.append({
                "time": datetime.now(timezone.utc).isoformat(),
                "action": ACTION_LABELS.get(action, action),
                "result": result,
                "actor": actor,
                "reason": reason,
            })
            db.update_incident(incident_id, actions_taken=actions_taken)

        return {"recorded": saved, "status": status, "result": result}


response_engine = ResponseEngine()
