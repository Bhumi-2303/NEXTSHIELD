#!/usr/bin/env python3
"""Train a LightGBM phishing classifier.

Usage:
    cd backend
    python -m app.modules.phishing.train --data ../../data/phishing/dataset.csv

Expects a CSV with at least these columns:
  - ``text``  : raw email text (subject + body concatenated)
  - ``label`` : 1 = phishing, 0 = legitimate

The script:
  1. Loads & preprocesses the CSV
  2. Synthesises features using the same pipeline as inference
  3. Trains a LightGBM binary classifier with 5-fold CV
  4. Saves the model to ``models/phishing_classifier.pkl``

Swap datasets by pointing ``--data`` at any CSV that has ``text`` and
``label`` columns (Kaggle "Phishing Email Dataset", Nazario + Enron, etc.).
"""

from __future__ import annotations

import argparse


import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score

try:
    import lightgbm as lgb
except ImportError:
    print("ERROR: lightgbm is not installed.  Run:  pip install lightgbm")
    sys.exit(1)

# Ensure the project root is on sys.path so relative imports work
_project_root = Path(__file__).resolve().parents[3]  # backend/
sys.path.insert(0, str(_project_root))

from app.modules.phishing.features import (
    FEATURE_NAMES,
    extract_all_features,
    extract_urls_from_text,
    features_to_model_input,
)


# ============================================================================
# Data loading & preprocessing
# ============================================================================

def load_dataset(csv_path: str) -> pd.DataFrame:
    """Load a phishing/legitimate email CSV.

    Handles common column-name variations.
    """
    df = pd.read_csv(csv_path)

    # Normalise column names
    col_map: dict[str, str] = {}
    for col in df.columns:
        low = col.strip().lower()
        if low in ("text", "email_text", "email", "body", "message", "content"):
            col_map[col] = "text"
        elif low in ("label", "class", "target", "is_phishing", "phishing"):
            col_map[col] = "label"
    df = df.rename(columns=col_map)

    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError(
            f"CSV must have 'text' and 'label' columns.  Found: {list(df.columns)}"
        )

    # Ensure label is binary int
    df["label"] = df["label"].astype(int)
    df = df.dropna(subset=["text"])
    df["text"] = df["text"].astype(str)
    print(f"Loaded {len(df)} samples  (phishing={df['label'].sum()}, "
          f"legit={len(df) - df['label'].sum()})")
    return df


def email_text_to_features(text: str) -> dict:
    """Convert a raw email text blob to the full feature dict.

    Since the CSV has no structured sender/headers/URLs, we synthesise
    reasonable values.
    """
    # Treat the first line as a pseudo-subject if it's short
    lines = text.strip().split("\n", 1)
    subject = lines[0][:200] if lines else ""
    body = lines[1] if len(lines) > 1 else text

    # Use a generic sender for training (features still extracted from text)
    sender = "unknown@unknown.com"
    headers: dict[str, str] = {}
    urls = extract_urls_from_text(body)

    return extract_all_features(sender, subject, body, headers, urls)


# ============================================================================
# Training
# ============================================================================

def train(csv_path: str, output_path: str = "models/phishing_classifier.pkl"):
    """Full training pipeline."""

    df = load_dataset(csv_path)

    # Extract features
    print("Extracting features...")
    feature_dicts = [email_text_to_features(t) for t in df["text"]]
    X = np.array([features_to_model_input(fd) for fd in feature_dicts])
    y = df["label"].values

    print(f"Feature matrix shape: {X.shape}")

    # Train LightGBM
    params = {
        "boosting_type": "gbdt",
        "objective": "binary",
        "n_estimators": 200,
        "max_depth": 6,
        "learning_rate": 0.05,
        "num_leaves": 31,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "min_child_samples": 20,
        "random_state": 42,
        "verbose": -1,
    }

    model = lgb.LGBMClassifier(**params)

    # Cross-validation
    print("Running 5-fold stratified cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring="roc_auc")
    print(f"CV ROC-AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Train final model on full data
    print("Training final model on full dataset...")
    model.fit(X, y)

    # Quick eval on training set
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)[:, 1]
    print(f"\nTraining set ROC-AUC: {roc_auc_score(y, y_proba):.4f}")
    print("\nClassification Report (training set):")
    print(classification_report(y, y_pred, target_names=["Legitimate", "Phishing"]))

    # Feature importances
    print("Feature importances:")
    for name, imp in sorted(
        zip(FEATURE_NAMES, model.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    ):
        print(f"  {name:35s} {imp:6d}")

    # Save model
    output = Path(output_path)
    if output.suffix == ".pkl":
        output = output.with_suffix(".txt")
    output.parent.mkdir(parents=True, exist_ok=True)
    model.booster_.save_model(str(output))
    print(f"\n✅ Model saved to {output}")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Train NEXTSHIELD phishing classifier")
    parser.add_argument(
        "--data",
        type=str,
        required=True,
        help="Path to CSV with 'text' and 'label' columns",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="models/phishing_classifier.pkl",
        help="Output path for the trained model pickle",
    )
    args = parser.parse_args()
    train(args.data, args.output)


if __name__ == "__main__":
    main()
