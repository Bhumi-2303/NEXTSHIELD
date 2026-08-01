"""Explainability module API routes."""

from typing import Any, Dict, List, Literal
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ...schemas.shap_explanation import SHAPExplanation
from .explain import explain_prediction

router = APIRouter(prefix="/explain", tags=["Explainability (XAI)"])


class ExplainRequest(BaseModel):
    """Payload to request an explanation for a feature vector."""

    feature_vector: Dict[str, Any] = Field(
        ...,
        example={
            "domain_age_days": 12,
            "spf_pass": 0,
            "urgency_score": 9,
            "link_count": 15,
            "attachment_count": 2,
        },
        description="Dictionary mapping feature names to their values.",
    )
    feature_names: List[str] = Field(
        ...,
        example=["domain_age_days", "spf_pass", "urgency_score", "link_count", "attachment_count"],
        description="Ordered list of feature names used by the model.",
    )
    model_type: Literal["tree", "other"] = Field(
        "tree",
        description="The type of the model (tree-based like LightGBM/XGBoost, or other).",
    )


_dummy_models: Dict[tuple[int, str], Any] = {}


def get_cached_dummy_model(num_features: int, model_type: str) -> Any:
    """Helper to lazily create and cache a dummy model for API demonstration."""
    import numpy as np
    cache_key = (num_features, model_type)
    if cache_key not in _dummy_models:
        X = np.random.rand(50, num_features)
        y = np.random.randint(0, 2, size=50)

        if model_type == "tree":
            try:
                import lightgbm as lgb
                model = lgb.LGBMClassifier(n_estimators=5, max_depth=3, random_state=42)
                model.fit(X, y)
            except ImportError:
                # Fallback to Scikit-Learn RandomForest if lightgbm is missing
                from sklearn.ensemble import RandomForestClassifier
                model = RandomForestClassifier(n_estimators=5, max_depth=3, random_state=42)
                model.fit(X, y)
        else:
            from sklearn.linear_model import LogisticRegression
            model = LogisticRegression(random_state=42)
            model.fit(X, y)

        _dummy_models[cache_key] = model
    return _dummy_models[cache_key]


@router.post("/", response_model=SHAPExplanation)
async def explain_prediction_endpoint(request: ExplainRequest):
    """Generate a SHAP explanation for a given feature vector.

    For demonstration purposes, if no pre-loaded model exists, this endpoint
    will dynamically train a dummy model in memory matching the requested schema.
    """
    if not request.feature_names:
        raise HTTPException(status_code=400, detail="feature_names cannot be empty")

    # Ensure all feature names are in the feature vector
    missing = [name for name in request.feature_names if name not in request.feature_vector]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"The following feature_names are missing from feature_vector: {missing}",
        )

    try:
        model = get_cached_dummy_model(len(request.feature_names), request.model_type)
        # Compute the explanation
        explanation = explain_prediction(
            model=model,
            feature_vector=request.feature_vector,
            feature_names=request.feature_names,
            model_type=request.model_type,
        )
        return explanation
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Explainability error: {str(e)}")
