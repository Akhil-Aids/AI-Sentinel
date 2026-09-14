"""Data quality center routes."""
from fastapi import APIRouter, Depends

from app.core.deps import require_privilege_at_least
from app.services import data_quality

router = APIRouter()


@router.get("/overview/")
def overview(_payload: dict = Depends(require_privilege_at_least("SOC_ANALYST"))) -> dict:
    return data_quality.overview()