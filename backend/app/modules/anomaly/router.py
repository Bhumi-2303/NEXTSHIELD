"""Anomaly detection module API routes.

Endpoints
---------
POST /analyze   — batch analysis of flow records (primary endpoint)
POST /detect    — single-flow analysis (backwards-compatible stub)
"""

from fastapi import APIRouter

from ...schemas.anomaly import NetworkAnomalyResult
from ...schemas.flow_request import FlowBatchRequest, FlowRecord
from .detector import detector

router = APIRouter(prefix="/anomaly", tags=["Network Anomaly Detection"])


@router.post("/analyze", response_model=list[NetworkAnomalyResult])
async def analyze_flows(request: FlowBatchRequest):
    """Analyse a batch of network flow records for anomalies.

    Runs the hybrid Isolation-Forest + XGBoost pipeline and returns
    a ``NetworkAnomalyResult`` for each flow, including:
    - Combined anomaly score (weighted ensemble)
    - Zero-day candidate flag
    - MITRE ATT&CK technique mapping
    """
    return detector.predict_batch(request.flows)


@router.post("/detect", response_model=NetworkAnomalyResult)
async def detect_anomaly(flow: FlowRecord):
    """Analyse a single network flow for anomalies.

    Convenience wrapper around ``/analyze`` for single-flow requests.
    Kept for backwards compatibility with the original API stub.
    """
    results = detector.predict_batch([flow])
    return results[0]
