"""Explainability module (XAI).

Responsible for:
- Computing SHAP explanations for any model prediction
- Attaching SHAPExplanation to ThreatAlert objects
- Generating human-readable reasoning strings
"""

from .explain import (
    FEATURE_TEMPLATES,
    explain_prediction,
    generate_incident_summary,
    get_plain_english_explanation,
)

__all__ = [
    "explain_prediction",
    "generate_incident_summary",
    "FEATURE_TEMPLATES",
    "get_plain_english_explanation",
]
