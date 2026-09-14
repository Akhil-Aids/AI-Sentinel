"""Global search route: cross-entity lookup grouped by entity type."""
from fastapi import APIRouter, Depends, Query

from app.core.deps import current_user
from app.services.search import search_all

router = APIRouter()


@router.get("/")
def search(
    q: str = Query(..., description="Search text (min 2 chars)"),
    limit: int = Query(5, ge=1, le=50),
    _payload: dict = Depends(current_user),
) -> dict:
    return search_all(q, limit=limit)