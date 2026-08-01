"""Explainability module API routes."""

from fastapi import APIRouter

from ...schemas.shap_explanation import SHAPExplanation

router = APIRouter(prefix="/explain", tags=["Explainability (XAI)"])


@router.post("/", response_model=SHAPExplanation)
async def explain_prediction():
    """Generate a SHAP explanation for a given alert.

    TODO: accept alert ID or raw features, run SHAP, return explanation.
    """
    raise NotImplementedError("Explainability not yet implemented.")
