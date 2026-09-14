"""Notifications routes — in-app notification center.

Any authenticated user can read/acknowledge notifications. Notifications are
created by the detection pipeline for high/critical alerts.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app import db
from app.core.deps import current_user

router = APIRouter()


@router.get("/")
def list_notifications(limit: int = Query(50, ge=1, le=200),
                       unread_only: bool = False,
                       _payload: dict = Depends(current_user)) -> dict:
    items = db.list_notifications(limit=limit, unread_only=unread_only)
    return {"items": items, "unread": db.count_unread_notifications()}


@router.get("/unread-count")
def unread_count(_payload: dict = Depends(current_user)) -> dict:
    return {"unread": db.count_unread_notifications()}


@router.post("/{notification_id}/read")
def mark_read(notification_id: str, _payload: dict = Depends(current_user)) -> dict:
    db.mark_notification_read(notification_id)
    return {"status": "ok", "notification_id": notification_id}


@router.post("/read-all")
def mark_all_read(_payload: dict = Depends(current_user)) -> dict:
    count = db.mark_all_notifications_read()
    return {"status": "ok", "marked": count}