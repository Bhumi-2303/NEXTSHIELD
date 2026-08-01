"""ThreatAlert — the universal alert envelope for NEXTSHIELD."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from ..core.constants import MITRETechnique, SeverityLevel
from .shap_explanation import SHAPExplanation


class ThreatAlert(BaseModel):
    """Base alert produced by any detection module.

    Every phishing or anomaly result inherits from this so the API,
    dashboard, and playbook engine all speak the same language.
    """

    id: UUID = Field(default_factory=uuid4, description="Unique alert identifier.")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="UTC time the alert was generated.",
    )
    source_module: Literal["phishing", "anomaly"] = Field(
        ..., description="Which detection module raised the alert."
    )
    severity: SeverityLevel = Field(
        ..., description="Alert severity."
    )
    mitre_technique_id: MITRETechnique = Field(
        ..., description="Mapped MITRE ATT&CK technique."
    )
    confidence_score: float = Field(
        ..., ge=0.0, le=1.0, description="Model confidence, 0-1."
    )
    raw_features: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw feature vector used for prediction.",
    )
    explanation: Optional[SHAPExplanation] = Field(
        None, description="SHAP explanation (populated by explainability module)."
    )
    recommended_playbook_id: Optional[str] = Field(
        None, description="ID of the suggested incident-response playbook."
    )
