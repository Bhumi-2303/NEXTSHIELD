"""Phishing model — load, predict, and build PhishingScanResult.

This module is the bridge between the feature extraction pipeline and the
shared ``PhishingScanResult`` schema.  The LightGBM model is trained
offline by ``train.py`` and loaded at startup from the configured path.

If no trained model exists, a **rule-based fallback** is used so the API
remains functional for demos before any model is trained.
"""

from __future__ import annotations

from pathlib import Path
import lightgbm as lgb
from typing import Any

import numpy as np

from ...core.config import settings
from ...core.constants import MITRETechnique, SeverityLevel
from ...core.logging import get_logger
from ...schemas.phishing import PhishingScanResult
from ...schemas.shap_explanation import SHAPExplanation, SHAPFeature
from .features import (
    extract_all_features,
    features_to_model_input,
)

logger = get_logger("phishing.model")

# ---------------------------------------------------------------------------
# Global model singleton (loaded once at startup)
# ---------------------------------------------------------------------------
_model: Any = None
_model_loaded: bool = False


def load_model(path: str | None = None) -> bool:
    """Load a pickled LightGBM model from disk.

    Returns ``True`` if a model was successfully loaded, ``False`` if the
    file does not exist (rule-based fallback will be used).
    """
    global _model, _model_loaded
    model_path = Path(path or settings.PHISHING_MODEL_PATH)
    if model_path.exists():
        try:
            _model = lgb.Booster(model_file=str(model_path))
            _model_loaded = True
            logger.info("Loaded phishing model from %s", model_path)
            return True
        except Exception as exc:
            logger.error("Failed to load LightGBM model from %s: %s", model_path, exc)
            _model = None
            _model_loaded = False
            return False
    else:
        _model = None
        _model_loaded = False
        logger.warning(
            "Phishing model not found at %s — using rule-based fallback",
            model_path,
        )
        return False


def _rule_based_score(features: dict[str, Any]) -> float:
    """Simple weighted-rule fallback when no ML model is available.

    Produces a confidence score in [0, 1] where higher = more likely phishing.
    """
    score = 0.0

    # Urgency
    score += features.get("urgency_score", 0.0) * 0.25

    # Domain age (young domains are suspicious)
    age = features.get("domain_age_days")
    if age is not None and age < 30:
        score += 0.20
    elif age is not None and age < 180:
        score += 0.08

    # Auth failures
    if not features.get("spf_pass", True):
        score += 0.10
    if not features.get("dkim_pass", True):
        score += 0.10
    if not features.get("dmarc_pass", True):
        score += 0.08

    # Lookalike domain
    if features.get("lookalike_domain_detected", False):
        score += 0.15

    # Shortened URLs
    if features.get("has_shortened_url", False):
        score += 0.08

    # Suspicious TLDs
    score += min(features.get("suspicious_tld_count", 0) * 0.06, 0.12)

    # Generic greeting
    if features.get("generic_greeting", False):
        score += 0.05

    # Spelling anomalies
    score += features.get("spelling_anomaly_score", 0.0) * 0.10

    return min(score, 1.0)


def _generate_explanation(
    features: dict[str, Any], confidence: float
) -> SHAPExplanation:
    """Build a human-readable SHAP-like explanation.

    When a real SHAP explainer is available (via the explainability module)
    this will be replaced.  For now we produce rule-based feature
    contributions to keep the API response contract fulfilled.
    """
    contributions: list[SHAPFeature] = []
    base_value = 0.3  # prior

    # Map features to human-readable reasons
    reasons: list[tuple[str, float, str]] = []

    urgency = features.get("urgency_score", 0.0)
    if urgency > 0.05:
        reasons.append(("urgency_score", urgency * 0.25,
                        f"Urgency/pressure language detected (score={urgency:.2f})"))

    age = features.get("domain_age_days")
    if age is not None and age < 30:
        reasons.append(("domain_age_days", 0.20,
                        f"Sender domain is only {age} day(s) old"))
    elif age is not None and age < 180:
        reasons.append(("domain_age_days", 0.08,
                        f"Sender domain is {age} days old (< 6 months)"))

    if not features.get("spf_pass", True):
        reasons.append(("spf_pass", 0.10, "SPF validation failed"))
    if not features.get("dkim_pass", True):
        reasons.append(("dkim_pass", 0.10, "DKIM validation failed"))
    if not features.get("dmarc_pass", True):
        reasons.append(("dmarc_pass", 0.08, "DMARC validation failed"))

    if features.get("lookalike_domain_detected"):
        brand = features.get("lookalike_closest_brand", "unknown")
        reasons.append(("lookalike_domain_detected", 0.15,
                        f"URL domain is a lookalike of '{brand}'"))

    if features.get("has_shortened_url"):
        reasons.append(("has_shortened_url", 0.08,
                        "Email contains shortened URLs (potential redirect)"))

    tld_count = features.get("suspicious_tld_count", 0)
    if tld_count > 0:
        reasons.append(("suspicious_tld_count", min(tld_count * 0.06, 0.12),
                        f"{tld_count} URL(s) use suspicious TLDs"))

    if features.get("generic_greeting"):
        reasons.append(("generic_greeting", 0.05,
                        "Uses generic greeting (e.g. 'Dear Customer')"))

    spelling = features.get("spelling_anomaly_score", 0.0)
    if spelling > 0.05:
        reasons.append(("spelling_anomaly_score", spelling * 0.10,
                        f"Spelling anomalies detected (score={spelling:.2f})"))

    # Sort by |contribution| descending, take top 5
    reasons.sort(key=lambda r: abs(r[1]), reverse=True)
    for name, value, reason in reasons[:5]:
        contributions.append(SHAPFeature(
            feature_name=name,
            shap_value=round(value, 4),
            human_readable_reason=reason,
        ))

    return SHAPExplanation(
        top_features=contributions,
        base_value=round(base_value, 4),
        prediction_value=round(confidence, 4),
    )


def _determine_severity(confidence: float) -> SeverityLevel:
    """Map confidence score to severity level."""
    if confidence >= 0.85:
        return SeverityLevel.CRITICAL
    elif confidence >= 0.65:
        return SeverityLevel.HIGH
    elif confidence >= 0.40:
        return SeverityLevel.MEDIUM
    else:
        return SeverityLevel.LOW


def predict(
    sender: str,
    subject: str,
    body: str,
    headers: dict[str, str] | None = None,
    urls: list[str] | None = None,
) -> PhishingScanResult:
    """Run phishing detection on a raw email and return a PhishingScanResult.

    Parameters
    ----------
    sender : str
        Sender email address.
    subject : str
        Email subject.
    body : str
        Email body (plain text or HTML).
    headers : dict | None
        Email headers for SPF/DKIM/DMARC parsing.
    urls : list[str] | None
        Pre-extracted URLs; extracted from body if not provided.

    Returns
    -------
    PhishingScanResult
        Fully populated alert matching the shared schema.
    """
    headers = headers or {}

    # 1. Extract features
    features = extract_all_features(sender, subject, body, headers, urls)

    # 2. Predict
    if _model_loaded and _model is not None:
        vec = features_to_model_input(features)
        arr = np.array([vec])
        try:
            # LightGBM predict returns probability of class 1 for binary classification
            proba = _model.predict(arr)
            confidence = float(proba[0])
        except Exception as exc:
            logger.error("Model prediction failed, falling back to rules: %s", exc)
            confidence = _rule_based_score(features)
    else:
        confidence = _rule_based_score(features)

    # 3. Build explanation
    explanation = _generate_explanation(features, confidence)

    # 4. Determine severity
    severity = _determine_severity(confidence)

    # 5. Recommended playbook
    playbook_id = "PB-T1566-001" if confidence >= 0.5 else None

    # 6. Build result
    return PhishingScanResult(
        source_module="phishing",
        severity=severity,
        mitre_technique_id=MITRETechnique.T1566,
        confidence_score=round(confidence, 4),
        raw_features={k: v for k, v in features.items()
                      if k not in ("url_reputation_flags", "sender_domain",
                                   "domain_age_days", "spf_pass", "dkim_pass",
                                   "dmarc_pass", "urgency_score")},
        explanation=explanation,
        recommended_playbook_id=playbook_id,
        # PhishingScanResult-specific fields
        sender_domain=features["sender_domain"],
        domain_age_days=features.get("domain_age_days"),
        spf_pass=features.get("spf_pass", False),
        dkim_pass=features.get("dkim_pass", False),
        dmarc_pass=features.get("dmarc_pass", False),
        urgency_score=features.get("urgency_score", 0.0),
        url_reputation_flags=features.get("url_reputation_flags", []),
    )
