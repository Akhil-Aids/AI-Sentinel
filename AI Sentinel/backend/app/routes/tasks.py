"""SOC task management routes (remediation / containment action tracking)."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app import db
from app.core.deps import client_ip, require_privilege_at_least

router = APIRouter()

TASK_STATUSES = ("TODO", "IN_PROGRESS", "DONE", "CANCELLED")
TASK_PRIORITIES = ("low", "medium", "high", "critical")


class TaskCreateRequest(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = ""
    owner: str = ""
    priority: str = "medium"
    due_at: str | None = None
    incident_id: str = ""
    case_id: str = ""


class TaskUpdateRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    owner: str | None = None
    priority: str | None = None
    status: str | None = None
    due_at: str | None = None


@router.post("/")
def create_task(body: TaskCreateRequest, request: Request,
                payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    if body.priority not in TASK_PRIORITIES:
        raise HTTPException(status_code=400, detail=f"Priority must be one of {', '.join(TASK_PRIORITIES)}")
    if body.incident_id and not db.get_incident(body.incident_id):
        raise HTTPException(status_code=404, detail="Incident not found")
    if body.case_id and not db.get_case(body.case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    task = db.create_task(task_id=db.new_id("tsk"), incident_id=body.incident_id,
                          case_id=body.case_id, title=body.title, description=body.description,
                          owner=body.owner, priority=body.priority, due_at=body.due_at,
                          created_by=payload["sub"])
    db.log_audit(actor=payload["sub"], role=payload["role"], action="task.create",
                 target=task["task_id"], ip=client_ip(request), detail={"priority": body.priority})
    return task


@router.get("/")
def list_tasks(incident_id: str | None = None, case_id: str | None = None,
               status: str | None = None, owner: str | None = None, limit: int = 200,
               _payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    return {"items": db.list_tasks(incident_id=incident_id, case_id=case_id,
                                   status=status, owner=owner, limit=limit)}


@router.patch("/{task_id}")
def update_task(task_id: str, body: TaskUpdateRequest, request: Request,
                payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    existing = db.get_task(task_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Task not found")
    fields = {}
    if body.title is not None:
        fields["title"] = body.title
    if body.description is not None:
        fields["description"] = body.description
    if body.owner is not None:
        fields["owner"] = body.owner
    if body.priority is not None:
        if body.priority not in TASK_PRIORITIES:
            raise HTTPException(status_code=400, detail="Invalid priority")
        fields["priority"] = body.priority
    if body.status is not None:
        if body.status not in TASK_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status")
        fields["status"] = body.status
        if body.status == "DONE" and not existing.get("completed_at"):
            fields["completed_at"] = db._now()
        if body.status != "DONE":
            fields["completed_at"] = None
    if body.due_at is not None:
        fields["due_at"] = body.due_at
    db.update_task(task_id, **fields)
    db.log_audit(actor=payload["sub"], role=payload["role"], action="task.update",
                 target=task_id, ip=client_ip(request), detail={k: v for k, v in fields.items()})
    return db.get_task(task_id)


@router.delete("/{task_id}")
def delete_task(task_id: str, request: Request,
                payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    if not db.get_task(task_id):
        raise HTTPException(status_code=404, detail="Task not found")
    db.delete_task(task_id)
    db.log_audit(actor=payload["sub"], role=payload["role"], action="task.delete",
                 target=task_id, ip=client_ip(request))
    return {"status": "ok"}