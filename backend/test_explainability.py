"""Test script for the NEXTSHIELD Explainability (XAI) module.

Trains a dummy LightGBM model, computes SHAP values, generates explanations,
and produces incident summaries (with both rule-based fallback and mock LLM).
"""

import sys
import numpy as np
import pandas as pd
import lightgbm as lgb

from app.modules.explainability import (
    explain_prediction,
    generate_incident_summary,
    FEATURE_TEMPLATES,
)
from app.schemas.threat_alert import ThreatAlert
from app.schemas.shap_explanation import SHAPExplanation
from app.core.constants import MITRETechnique, SeverityLevel


def run_test():
    print("=" * 70)
    print("STARTING EXPLAINABILITY MODULE INTEGRATION TEST")
    print("=" * 70)

    # 1. Define feature names and templates
    feature_names = [
        "domain_age_days",
        "spf_pass",
        "urgency_score",
        "link_count",
        "attachment_count",
    ]

    print(f"Features for explanation: {feature_names}\n")

    # 2. Generate a dummy dataset to train a basic LightGBM classifier
    np.random.seed(42)
    n_samples = 200
    
    # Simulating data:
    # - domain_age_days: younger domain -> higher chance of phishing (class 1)
    # - spf_pass: fail (0) -> higher chance of phishing (class 1)
    # - urgency_score: high -> higher chance of phishing (class 1)
    domain_age = np.random.randint(1, 3000, size=n_samples)
    spf = np.random.choice([0, 1], p=[0.3, 0.7], size=n_samples)
    urgency = np.random.randint(0, 10, size=n_samples)
    links = np.random.randint(0, 20, size=n_samples)
    attachments = np.random.randint(0, 5, size=n_samples)

    # Build target y based on rules to make it easy to learn
    # domain_age < 30 days OR (spf_pass == 0 AND urgency_score > 6) -> phishing
    y = np.where((domain_age < 90) | ((spf == 0) & (urgency > 5)), 1, 0)
    
    # Put into a DataFrame
    X = pd.DataFrame({
        "domain_age_days": domain_age,
        "spf_pass": spf,
        "urgency_score": urgency,
        "link_count": links,
        "attachment_count": attachments,
    })

    print(f"Training dummy LightGBM classifier on {n_samples} samples...")
    model = lgb.LGBMClassifier(
        n_estimators=10,
        max_depth=3,
        learning_rate=0.1,
        random_state=42,
        verbosity=-1
    )
    model.fit(X, y)
    print("Model trained successfully.\n")

    # 3. Create a malicious-looking feature vector (anomalous/phishing)
    # domain_age_days is 12 (very young), spf_pass is 0 (fail), urgency_score is 9 (high urgency)
    test_features = {
        "domain_age_days": 12,
        "spf_pass": 0,
        "urgency_score": 9,
        "link_count": 15,
        "attachment_count": 2,
    }
    
    print(f"Test feature vector: {test_features}")
    
    # 4. Generate SHAP explanation using explain_prediction
    print("\nComputing SHAP explanation...")
    explanation = explain_prediction(
        model=model,
        feature_vector=test_features,
        feature_names=feature_names,
        model_type="tree"
    )
    
    # Assertions to ensure schema correctness
    assert isinstance(explanation, SHAPExplanation), "Output is not a SHAPExplanation object"
    assert len(explanation.top_features) <= 5, "More than 5 features returned"
    
    # Ensure features are sorted by absolute SHAP value descending
    vals = [abs(f.shap_value) for f in explanation.top_features]
    assert vals == sorted(vals, reverse=True), "Features are not sorted by absolute SHAP value descending"

    print("SHAP explanation computed successfully!")
    print(f"Base Value (Expected log-odds/prob): {explanation.base_value:.4f}")
    print(f"Prediction Value (Output log-odds/prob): {explanation.prediction_value:.4f}")
    print("\nTop Contributing Features:")
    for idx, feat in enumerate(explanation.top_features, 1):
        print(f"  {idx}. {feat.feature_name}: SHAP={feat.shap_value:+.4f}")
        print(f"     Reason: {feat.human_readable_reason}")

    # 5. Create a universal ThreatAlert envelope
    alert = ThreatAlert(
        source_module="phishing",
        severity=SeverityLevel.HIGH,
        mitre_technique_id=MITRETechnique.T1566,
        confidence_score=0.92,
        raw_features=test_features,
        explanation=explanation
    )

    # 6. Generate summary with rule-based fallback
    print("\n" + "-"*50)
    print("TESTING INCIDENT SUMMARY (RULE-BASED FALLBACK)")
    print("-"*50)
    fallback_summary = generate_incident_summary(alert)
    print(f"Fallback Summary:\n{fallback_summary}")
    
    # Ensure it's a non-empty string and has multiple sentences
    assert isinstance(fallback_summary, str) and len(fallback_summary) > 0
    assert fallback_summary.count(".") >= 2, "Summary should be 2-3 sentences"

    # 7. Generate summary with injected LLM client
    print("\n" + "-"*50)
    print("TESTING INCIDENT SUMMARY (MOCKED LLM CLIENT)")
    print("-"*50)
    
    # Mock OpenAI-like client
    class MockOpenAI:
        class Chat:
            class Completions:
                def create(self, model, messages, **kwargs):
                    # Simulating a 2-3 sentence AI summary
                    return {
                        "choices": [{
                            "message": {
                                "content": (
                                    "NEXTSHIELD detected a critical phishing attempt targeting the organization. "
                                    "The alert was triggered by a newly registered email domain combined with an "
                                    "extremely high urgency score and failed SPF sender verification. "
                                    "Security personnel should immediately quarantine the message and inspect links."
                                )
                            }
                        }]
                    }
            completions = Completions()
        chat = Chat()

    mock_client = MockOpenAI()
    llm_summary = generate_incident_summary(alert, client=mock_client, model="gpt-4o")
    print(f"Injected LLM Summary:\n{llm_summary}")
    
    assert "quarantine the message" in llm_summary
    print("\n" + "="*70)
    print("ALL TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    try:
        run_test()
        sys.exit(0)
    except Exception as e:
        import traceback
        traceback.print_exc()
        sys.exit(1)
