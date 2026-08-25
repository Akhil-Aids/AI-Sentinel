"""ML model status and manual training routes."""
from fastapi import APIRouter, Depends

from app.core.deps import current_user, require_privilege_at_least
from app.ml.anomaly import anomaly_detector

router = APIRouter()


@router.get("/status")
def ml_status(_payload: dict = Depends(current_user)) -> dict:
    """Current ML model status, metadata, and drift metrics."""
    return anomaly_detector.status()


@router.post("/train")
def ml_train(_payload: dict = Depends(require_privilege_at_least("ADMIN"))) -> dict:
    """Manually trigger model retraining on accumulated samples."""
    result = anomaly_detector.retrain()
    return {"status": "ok", **result}
