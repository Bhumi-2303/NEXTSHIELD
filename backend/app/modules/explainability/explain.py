"""Explainability services for NEXTSHIELD.

Provides generic SHAP explanation wrapping and incident summary generation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Literal, Optional, Union

import numpy as np
import pandas as pd
import shap

from ...core.logging import get_logger
from ...schemas.shap_explanation import SHAPExplanation, SHAPFeature
from ...schemas.threat_alert import ThreatAlert

logger = get_logger("explainability")

# Small dictionary mapping technical feature names to plain-English explanation templates
FEATURE_TEMPLATES: Dict[str, str] = {
    # Phishing features
    "domain_age_days": "the sender's domain is only {value} days old, which is typical for newly registered malicious domains",
    "spf_pass": "the email failed Sender Policy Framework (SPF) validation (value: {value}), indicating potential sender spoofing",
    "urgency_score": "the email content exhibits a high urgency score of {value}, which is a common psychological trigger in phishing",
    "link_count": "the email contains {value} external links, which is unusually high and increases the risk of malicious redirection",
    "attachment_count": "the email contains {value} attachments, a common delivery mechanism for malware",
    "subject_entropy": "the email subject has an entropy of {value}, indicating high randomness or obfuscation",
    "dmarc_pass": "the email failed DMARC alignment validation (value: {value}), suggesting unauthorized domain use",
    "dkim_pass": "the email failed DomainKeys Identified Mail (DKIM) signature validation (value: {value})",

    # Network features
    "flow_duration": "the connection persisted for {value} seconds, suggesting a prolonged data transfer or persistent tunnel",
    "packet_count": "a total of {value} packets were transmitted, which may indicate data exfiltration or scanning activity",
    "anomaly_score": "the traffic flow has a high network anomaly score of {value}, deviating significantly from established baselines",
    "byte_count": "a total of {value} bytes were transferred, indicating a large payload transfer typical of exfiltration",
    "dest_port": "the connection targeted destination port {value}, which is associated with potentially unauthorized or vulnerable services",
    "protocol": "the connection used protocol {value}, which might be anomalous for the source-destination pair",
    "connection_count": "there were {value} concurrent connections observed, indicating potential port scanning or denial-of-service attempts",
}


def get_plain_english_explanation(feature_name: str, feature_value: Any) -> str:
    """Helper to convert a feature value into a plain English explanation using templates."""
    template = FEATURE_TEMPLATES.get(feature_name)
    if template:
        try:
            return template.format(value=feature_value)
        except Exception as e:
            logger.warning("Failed to format template for %s: %s", feature_name, e)
            return f"the feature '{feature_name}' had a value of {feature_value}"
    else:
        # Fallback: convert underscores to spaces for readability
        readable_name = feature_name.replace("_", " ")
        return f"the {readable_name} was {feature_value}"


def explain_prediction(
    model: Any,
    feature_vector: Union[Dict[str, Any], List[Any], np.ndarray, pd.DataFrame, pd.Series],
    feature_names: List[str],
    model_type: Literal["tree", "other"]
) -> SHAPExplanation:
    """Compute SHAP explanation for a single prediction vector.

    Args:
        model: The trained ML model (LightGBM, XGBoost, Scikit-Learn, etc.).
        feature_vector: The inputs of the single prediction.
        feature_names: Names of features in the order expected by the model.
        model_type: "tree" for tree-based models, "other" for non-tree models.

    Returns:
        SHAPExplanation object containing top 5 contributing features.
    """
    # 1. Standardize feature_vector into a 1-row pandas DataFrame matching feature_names
    if isinstance(feature_vector, dict):
        df = pd.DataFrame([[feature_vector.get(name, 0.0) for name in feature_names]], columns=feature_names)
    elif isinstance(feature_vector, (list, np.ndarray)):
        arr = np.array(feature_vector).reshape(1, -1)
        if arr.shape[1] != len(feature_names):
            raise ValueError(f"Feature vector length ({arr.shape[1]}) does not match feature_names length ({len(feature_names)})")
        df = pd.DataFrame(arr, columns=feature_names)
    elif isinstance(feature_vector, pd.DataFrame):
        df = feature_vector[feature_names].copy()
    elif isinstance(feature_vector, pd.Series):
        df = pd.DataFrame([feature_vector.reindex(feature_names)])
    else:
        raise TypeError(f"Unsupported feature_vector type: {type(feature_vector)}")

    # 2. Compute SHAP values based on model type
    if model_type == "tree":
        explainer = shap.TreeExplainer(model)
        # Use TreeExplainer's shap_values
        shap_values_raw = explainer.shap_values(df)
        base_values_raw = explainer.expected_value
    else:
        # Try shap.Explainer, fallback to KernelExplainer if it fails
        try:
            explainer = shap.Explainer(model, df)
            shap_values_raw = explainer(df).values
            base_values_raw = explainer(df).base_values
        except Exception as e:
            logger.debug("shap.Explainer failed (%s), falling back to KernelExplainer", e)
            # Find prediction function
            predict_fn = getattr(model, "predict_proba", getattr(model, "predict", None))
            if predict_fn is None:
                raise ValueError("Model does not have a predict or predict_proba method.")

            # Simple background dataset of zeroes
            background = pd.DataFrame([[0.0] * len(feature_names)], columns=feature_names)
            explainer = shap.KernelExplainer(predict_fn, background)
            shap_values_raw = explainer.shap_values(df)
            base_values_raw = explainer.expected_value

    # 3. Parse SHAP values to extract 1D contributions vector and scalar base value
    # Handle modern Explanation objects
    if hasattr(shap_values_raw, "values"):
        vals = shap_values_raw.values
        if len(vals.shape) == 3:
            # Binary classifier: (samples, features, classes) -> take class 1
            shap_vector = vals[0, :, 1] if vals.shape[2] == 2 else vals[0, :, -1]
        elif len(vals.shape) == 2:
            shap_vector = vals[0, :]
        else:
            shap_vector = vals.flatten()

        if hasattr(shap_values_raw, "base_values"):
            bv = shap_values_raw.base_values
            if isinstance(bv, (np.ndarray, list)):
                base_value = float(bv[0, 1] if len(bv.shape) > 1 and bv.shape[1] == 2 else bv[0])
            else:
                base_value = float(bv)
        else:
            base_value = float(base_values_raw)

    # Handle lists of arrays (classic TreeExplainer return value for binary classifiers)
    elif isinstance(shap_values_raw, list):
        if len(shap_values_raw) == 2:
            # Class 1 contributions
            shap_vector = shap_values_raw[1][0]
        else:
            shap_vector = shap_values_raw[0][0]

        if isinstance(base_values_raw, (list, np.ndarray)):
            base_value = float(base_values_raw[1] if len(base_values_raw) == 2 else base_values_raw[0])
        else:
            base_value = float(base_values_raw)

    # Handle standard numpy array output
    elif isinstance(shap_values_raw, np.ndarray):
        if shap_values_raw.ndim == 3:
            if shap_values_raw.shape[0] == 2:
                # Class 1 contributions
                shap_vector = shap_values_raw[1][0]
            elif shap_values_raw.shape[2] == 2:
                # (samples, features, classes)
                shap_vector = shap_values_raw[0, :, 1]
            else:
                shap_vector = shap_values_raw[-1][0]
        elif shap_values_raw.ndim == 2:
            if shap_values_raw.shape[0] == 1:
                shap_vector = shap_values_raw[0]
            elif shap_values_raw.shape[1] == 2:
                # (features, classes)
                shap_vector = shap_values_raw[:, 1]
            else:
                shap_vector = shap_values_raw[:, 0]
        else:
            shap_vector = shap_values_raw.flatten()

        if isinstance(base_values_raw, (list, np.ndarray)):
            base_value = float(base_values_raw[1] if len(base_values_raw) == 2 else base_values_raw[0])
        else:
            base_value = float(base_values_raw)
    else:
        raise TypeError(f"Unexpected SHAP values type returned: {type(shap_values_raw)}")

    # 4. Generate SHAPFeature list, sort, and select top 5
    feature_contributions = []
    for i, name in enumerate(feature_names):
        shap_val = float(shap_vector[i])
        feat_val = df.iloc[0][name]

        # Format values for readable string representation
        if isinstance(feat_val, (np.floating, float)):
            feat_val_formatted = round(float(feat_val), 4)
        elif isinstance(feat_val, (np.integer, int)):
            feat_val_formatted = int(feat_val)
        else:
            feat_val_formatted = feat_val

        plain_english_explanation = get_plain_english_explanation(name, feat_val_formatted)
        sign = "+" if shap_val >= 0 else "-"
        
        # Follow requested template:
        # "{feature_name} contributed {+/-} {value} toward this being flagged, because {plain_english_explanation}"
        reason = f"{name} contributed {sign} {abs(shap_val):.4f} toward this being flagged, because {plain_english_explanation}"

        feature_contributions.append({
            "name": name,
            "shap_value": shap_val,
            "abs_shap_value": abs(shap_val),
            "reason": reason
        })

    # Sort by absolute SHAP value descending
    feature_contributions.sort(key=lambda x: x["abs_shap_value"], reverse=True)
    top_5 = feature_contributions[:5]

    shap_features = [
        SHAPFeature(
            feature_name=item["name"],
            shap_value=item["shap_value"],
            human_readable_reason=item["reason"]
        )
        for item in top_5
    ]

    # Calculate prediction value self-consistently
    prediction_value = float(base_value + np.sum(shap_vector))

    return SHAPExplanation(
        top_features=shap_features,
        base_value=base_value,
        prediction_value=prediction_value
    )


def generate_incident_summary(
    alert: ThreatAlert,
    client: Optional[Any] = None,
    model: Optional[str] = None
) -> str:
    """Produce a 2-3 sentence plain-English incident summary for a non-technical stakeholder.

    Accepts an optional injected client (OpenAI, Anthropic, or callable function)
    to perform LLM generation. Falls back to a deterministic rule-based generator
    if no client is provided or if the client call fails.

    Args:
        alert: The threat alert to summarize. Must contain a SHAP explanation.
        client: Optional injected LLM client.
        model: Optional model identifier for the LLM.

    Returns:
        A 2-3 sentence summary string.
    """
    if not alert.explanation or not alert.explanation.top_features:
        return "No explanation details are available for this alert."

    # If client is provided, try calling the LLM
    if client is not None:
        features_desc = "\n".join([
            f"- {feat.feature_name} (SHAP contribution: {feat.shap_value:+.4f}): {feat.human_readable_reason}"
            for feat in alert.explanation.top_features
        ])
        
        mitre_display = alert.mitre_technique_id.display_name if hasattr(alert.mitre_technique_id, "display_name") else str(alert.mitre_technique_id)
        mitre_val = alert.mitre_technique_id.value if hasattr(alert.mitre_technique_id, "value") else str(alert.mitre_technique_id)
        severity_val = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)

        prompt = f"""You are an expert security analyst explaining a threat alert to a non-technical stakeholder.
Here are the details of the alert detected by NEXTSHIELD:
- Source Module: {alert.source_module}
- Severity: {severity_val}
- Confidence Score: {alert.confidence_score:.2%}
- MITRE ATT&CK Technique: {mitre_display} (ID: {mitre_val})

Key contributing features identified by SHAP (SHapley Additive exPlanations):
{features_desc}

Based on this information, write a concise 2-3 sentence plain-English incident summary suitable for a non-technical stakeholder.
Do NOT use technical machine learning jargon like "SHAP values", "feature vectors", or "expected value" in the summary.
Explain clearly what happened, why it was flagged, and the key indicators of the threat.
"""
        try:
            # 1. Check if client is directly callable
            if callable(client):
                return client(prompt).strip()

            # 2. OpenAI-like client
            if hasattr(client, "chat") and hasattr(client.chat, "completions"):
                response = client.chat.completions.create(
                    model=model or "gpt-4o",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3,
                    max_tokens=150
                )
                if hasattr(response, "choices") and len(response.choices) > 0:
                    return response.choices[0].message.content.strip()
                elif isinstance(response, dict) and "choices" in response:
                    return response["choices"][0]["message"]["content"].strip()

            # 3. Anthropic-like client
            if hasattr(client, "messages") and hasattr(client.messages, "create"):
                response = client.messages.create(
                    model=model or "claude-3-5-sonnet",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=150,
                    temperature=0.3
                )
                if hasattr(response, "content"):
                    if isinstance(response.content, list) and len(response.content) > 0:
                        return response.content[0].text.strip()
                    else:
                        return str(response.content).strip()
                elif isinstance(response, dict) and "content" in response:
                    return response["content"][0]["text"].strip()

            # 4. Gemini-like client
            if hasattr(client, "generate_content"):
                response = client.generate_content(prompt)
                if hasattr(response, "text"):
                    return response.text.strip()
                else:
                    return str(response).strip()

        except Exception as e:
            logger.warning("Injected LLM client failed: %s. Falling back to rule-based summary.", e)

    # Deterministic rule-based fallback summary (used if no client or LLM call failed)
    top_features = alert.explanation.top_features
    reasons = []
    for feat in top_features:
        # Extract the explanation part after "because "
        parts = feat.human_readable_reason.split("because ")
        if len(parts) > 1:
            reasons.append(parts[-1])
        else:
            reasons.append(feat.human_readable_reason)


    severity = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
    confidence = alert.confidence_score
    mitre_name = alert.mitre_technique_id.display_name if hasattr(alert.mitre_technique_id, "display_name") else str(alert.mitre_technique_id)

    if len(reasons) >= 2:
        reason_phrase = f"{reasons[0]} and {reasons[1]}"
    elif len(reasons) == 1:
        reason_phrase = f"{reasons[0]}"
    else:
        reason_phrase = "anomalous activity detected in the system features"

    if alert.source_module == "phishing":
        summary = (
            f"NEXTSHIELD flagged a potential phishing email (severity: {severity}) targeting the organization with a confidence score of {confidence:.1%}. "
            f"The detection was primarily triggered because {reason_phrase}. "
            f"This activity is mapped to the MITRE ATT&CK technique for {mitre_name}."
        )
    else:
        summary = (
            f"NEXTSHIELD detected an anomalous network connection (severity: {severity}) with a confidence score of {confidence:.1%}. "
            f"This network flow deviated from normal baseline behavior because {reason_phrase}. "
            f"It represents a potential security incident related to MITRE ATT&CK's {mitre_name}."
        )

    return summary
