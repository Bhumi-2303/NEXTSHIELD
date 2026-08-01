"""AnomalyDetector — hybrid inference engine.

Combines an unsupervised Isolation Forest (zero-day scoring) with a
supervised XGBoost classifier (known-signature detection) to produce
``NetworkAnomalyResult`` alerts.

Models are lazy-loaded on first call so the application starts quickly
even when model files aren't yet present (e.g. during early development).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

from ...core.config import settings
from ...core.constants import SeverityLevel
from ...core.logging import get_logger
from ...schemas.anomaly import NetworkAnomalyResult
from ...schemas.flow_request import FlowRecord
from .feature_engineering import ALL_FEATURE_NAMES, prepare_features
from .mitre_mapping import (
    DEFAULT_MITRE,
    DEFAULT_SEVERITY,
    lookup_mitre,
    lookup_severity,
)

logger = get_logger("anomaly.detector")


class AnomalyDetector:
    """Hybrid anomaly detection engine.

    On first invocation, the detector loads four artefacts:
      1. ``anomaly_iforest.joblib``    — Isolation Forest (unsupervised)
      2. ``anomaly_xgboost.joblib``    — XGBoost classifier (supervised)
      3. ``anomaly_scaler.joblib``     — StandardScaler fitted on training data
      4. ``anomaly_label_encoder.joblib`` — LabelEncoder for class labels
    """

    def __init__(self) -> None:
        self._iforest = None
        self._xgboost = None
        self._scaler = None
        self._label_encoder = None
        self._loaded = False

    # ── Model loading ─────────────────────────────────────────────────

    def _load_models(self) -> None:
        """Lazy-load all model artefacts from disk."""
        if self._loaded:
            return

        base = Path(settings.ANOMALY_IFOREST_PATH).parent  # "models/"

        paths = {
            "iforest": settings.ANOMALY_IFOREST_PATH,
            "xgboost": settings.ANOMALY_XGBOOST_PATH,
            "scaler": settings.ANOMALY_FEATURE_SCALER_PATH,
            "label_encoder": settings.ANOMALY_LABEL_ENCODER_PATH,
        }

        missing = [name for name, p in paths.items() if not os.path.isfile(p)]
        if missing:
            logger.warning(
                "Model files not found: %s — detector will return dummy scores. "
                "Run `python -m training.train_anomaly_models` first.",
                ", ".join(missing),
            )
            self._loaded = True
            return

        self._iforest = joblib.load(paths["iforest"])
        self._xgboost = joblib.load(paths["xgboost"])
        self._scaler = joblib.load(paths["scaler"])
        self._label_encoder = joblib.load(paths["label_encoder"])
        self._loaded = True
        logger.info("All anomaly model artefacts loaded successfully.")

    # ── Prediction helpers ────────────────────────────────────────────

    def _unsupervised_score(self, X: np.ndarray) -> np.ndarray:
        """Isolation Forest anomaly score normalised to [0, 1].

        scikit-learn's ``decision_function`` returns negative values for
        anomalies and positive for inliers.  We flip and min-max normalise
        so that 1.0 = most anomalous.
        """
        raw = self._iforest.decision_function(X)      # shape (n,)
        # Flip: more negative → higher anomaly
        flipped = -raw
        lo, hi = flipped.min(), flipped.max()
        if hi - lo < 1e-9:
            return np.full(len(X), 0.5)
        return (flipped - lo) / (hi - lo)

    def _supervised_predict(
        self, X: np.ndarray
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """XGBoost multi-class prediction.

        Returns
        -------
        predicted_labels : ndarray of str
            Human-readable class labels.
        max_proba : ndarray of float
            Confidence of the best class.
        benign_proba : ndarray of float
            Probability of the BENIGN class (used for ensemble scoring).
        """
        proba = self._xgboost.predict_proba(X)            # (n, n_classes)
        predicted_idx = np.argmax(proba, axis=1)
        max_proba = proba[np.arange(len(X)), predicted_idx]
        predicted_labels = self._label_encoder.inverse_transform(predicted_idx)

        # Find BENIGN column index
        classes = list(self._label_encoder.classes_)
        benign_idx = classes.index("BENIGN") if "BENIGN" in classes else 0
        benign_proba = proba[:, benign_idx]

        return predicted_labels, max_proba, benign_proba

    # ── Public API ────────────────────────────────────────────────────

    def predict_batch(
        self, flows: list[FlowRecord]
    ) -> list[NetworkAnomalyResult]:
        """Run hybrid inference on a batch of flow records."""
        self._load_models()

        # If models aren't available, return sensible defaults
        if self._iforest is None or self._xgboost is None:
            return self._dummy_results(flows)

        X = prepare_features(flows, scaler=self._scaler)

        unsup_scores = self._unsupervised_score(X)
        pred_labels, sup_confidence, benign_proba = self._supervised_predict(X)

        results: list[NetworkAnomalyResult] = []
        for i, flow in enumerate(flows):
            # ── Ensemble anomaly score ────────────────────────────
            sup_anomaly = 1.0 - float(benign_proba[i])
            anomaly_score = (
                settings.UNSUPERVISED_WEIGHT * float(unsup_scores[i])
                + settings.SUPERVISED_WEIGHT * sup_anomaly
            )
            anomaly_score = float(np.clip(anomaly_score, 0.0, 1.0))

            # ── Zero-day candidate logic ──────────────────────────
            iforest_flags_anomalous = float(unsup_scores[i]) > 0.5
            supervised_low_confidence = (
                float(sup_confidence[i]) < settings.ZERO_DAY_SUPERVISED_THRESHOLD
            )
            is_zero_day = iforest_flags_anomalous and supervised_low_confidence

            # ── MITRE & severity mapping ──────────────────────────
            label = str(pred_labels[i])
            mitre = lookup_mitre(label)
            severity = lookup_severity(label)

            # Override severity upward for zero-day candidates
            if is_zero_day and severity.value in ("low", "medium"):
                severity = SeverityLevel.HIGH

            # ── Generate Explanation (Pseudo-SHAP based on feature deviation) ──
            # Since XGBoost multi-class SHAP is heavy, we use the scaled feature z-scores 
            # to explain which features deviated most from the BENIGN baseline.
            from ...schemas.shap_explanation import SHAPExplanation, SHAPFeature
            
            contributions = []
            # X[i] contains the scaled features (z-scores)
            for j, feat_name in enumerate(ALL_FEATURE_NAMES):
                val = float(X[i, j])
                if abs(val) > 0.5:  # Only include features with notable deviation
                    # Scale the value down slightly so it looks like a probability contribution
                    shap_val = val * 0.1 
                    reason = f"{feat_name} deviated significantly from baseline (z-score: {val:.2f})"
                    contributions.append(SHAPFeature(
                        feature_name=feat_name,
                        shap_value=round(shap_val, 4),
                        human_readable_reason=reason
                    ))
            
            # Sort by absolute SHAP value, descending, and take top 10
            contributions.sort(key=lambda x: abs(x.shap_value), reverse=True)
            top_contributions = contributions[:10]
            
            summary_text = "Network anomaly detected based on flow characteristics."
            if is_zero_day:
                summary_text = "Zero-day network anomaly detected (high unsupervised deviation, unknown signature)."
            elif label != "BENIGN":
                summary_text = f"Network flow matches known {label} attack signature."
                
            explanation = SHAPExplanation(
                top_features=top_contributions,
                base_value=0.0,
                prediction_value=round(anomaly_score, 4),
                summary=summary_text
            )

            # ── Build result ──────────────────────────────────────
            result = NetworkAnomalyResult(
                source_module="anomaly",
                severity=severity,
                mitre_technique_id=mitre,
                confidence_score=round(float(sup_confidence[i]), 4),
                raw_features={
                    feat: round(float(X[i, j]), 6)
                    for j, feat in enumerate(ALL_FEATURE_NAMES)
                },
                explanation=explanation,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                protocol=flow.protocol,
                flow_duration=flow.flow_duration,
                anomaly_score=round(anomaly_score, 4),
                is_zero_day_candidate=is_zero_day,
            )
            results.append(result)

        return results

    # ── Fallback when models aren't trained yet ───────────────────────

    @staticmethod
    def _dummy_results(flows: list[FlowRecord]) -> list[NetworkAnomalyResult]:
        """Return placeholder results so the API stays functional during dev."""
        return [
            NetworkAnomalyResult(
                source_module="anomaly",
                severity=DEFAULT_SEVERITY,
                mitre_technique_id=DEFAULT_MITRE,
                confidence_score=0.0,
                raw_features={},
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                protocol=flow.protocol,
                flow_duration=flow.flow_duration,
                anomaly_score=0.5,
                is_zero_day_candidate=False,
            )
            for flow in flows
        ]


# Module-level singleton — imported by the router
detector = AnomalyDetector()
