"""Anomaly detection module API routes."""

from fastapi import APIRouter

from ...schemas.anomaly import NetworkAnomalyResult

router = APIRouter(prefix="/anomaly", tags=["Network Anomaly Detection"])


@router.post("/detect", response_model=NetworkAnomalyResult)
async def detect_anomaly():
    """Analyse a network flow for anomalies.

    TODO: accept flow features, run model, return result.
    """
    raise NotImplementedError("Anomaly detection not yet implemented.")
