"""SHAPExplanation schema — XAI output attached to every ThreatAlert."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SHAPFeature(BaseModel):
    """A single feature contribution from SHAP."""

    feature_name: str = Field(..., description="Name of the input feature.")
    shap_value: float = Field(
        ..., description="SHAP value (positive = pushes toward positive class)."
    )
    human_readable_reason: str = Field(
        ...,
        description="Plain-English explanation, e.g. 'Domain registered <24 h ago'.",
    )


class SHAPExplanation(BaseModel):
    """Container for SHAP-based model explanation."""

    top_features: list[SHAPFeature] = Field(
        ..., description="Features ranked by |SHAP value|, descending."
    )
    base_value: float = Field(
        ..., description="Expected model output (before feature contributions)."
    )
    prediction_value: float = Field(
        ..., description="Final model output after all contributions."
    )
