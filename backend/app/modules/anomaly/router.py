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


from typing import Dict, Any
from pydantic import BaseModel
from ...core.constants import MITRETechnique, SeverityLevel
from ...schemas.explainability import SHAPExplanation, SHAPFeature

class FlowPayload(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str
    bytes_out: int
    bytes_in: int
    duration_s: float
    flags: str

@router.post("/detect", response_model=NetworkAnomalyResult)
async def detect_anomaly():
    """Analyse a network flow for anomalies.

    TODO: accept flow features, run model, return result.
    """
    raise NotImplementedError("Anomaly detection not yet implemented.")
