"""Feature engineering for network flow anomaly detection.

Transforms a FlowRecord (or a DataFrame of flow records) into the numeric
feature matrix expected by the Isolation Forest and XGBoost models.

The feature order and transformations here **must** mirror the training
pipeline in ``backend/training/train_anomaly_models.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np
import pandas as pd

if TYPE_CHECKING:
    from ...schemas.flow_request import FlowRecord

# ── Canonical feature column order ────────────────────────────────────────
# This is the single source of truth for column ordering.  Both the
# training script and the inference path import this list.

NUMERIC_FEATURES: list[str] = [
    "flow_duration",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "src_port",
    "dst_port",
]

PROTOCOL_CATEGORIES: list[str] = ["TCP", "UDP", "ICMP"]

ALL_FEATURE_NAMES: list[str] = NUMERIC_FEATURES + [
    f"protocol_{p}" for p in PROTOCOL_CATEGORIES
]


def _encode_protocol(protocol: str) -> dict[str, int]:
    """One-hot encode the protocol field."""
    upper = protocol.upper()
    return {f"protocol_{p}": int(upper == p) for p in PROTOCOL_CATEGORIES}


def flow_record_to_dict(flow: "FlowRecord") -> dict[str, float]:
    """Convert a single FlowRecord to a flat feature dict."""
    d: dict[str, float] = {feat: getattr(flow, feat) for feat in NUMERIC_FEATURES}
    d.update(_encode_protocol(flow.protocol))
    return d


def flow_records_to_dataframe(flows: list["FlowRecord"]) -> pd.DataFrame:
    """Convert a batch of FlowRecords into a DataFrame with canonical column order."""
    rows = [flow_record_to_dict(f) for f in flows]
    df = pd.DataFrame(rows, columns=ALL_FEATURE_NAMES)
    return df


def apply_log_transform(df: pd.DataFrame) -> pd.DataFrame:
    """Apply log1p to high-variance byte/packet columns to compress outliers."""
    log_cols = ["fwd_bytes", "bwd_bytes", "fwd_packets", "bwd_packets"]
    df = df.copy()
    for col in log_cols:
        if col in df.columns:
            df[col] = np.log1p(df[col].astype(float))
    return df


def prepare_features(
    flows: list["FlowRecord"],
    scaler=None,
) -> np.ndarray:
    """Full pipeline: FlowRecords → scaled numpy feature matrix.

    Parameters
    ----------
    flows:
        List of incoming flow records.
    scaler:
        A fitted ``sklearn.preprocessing.StandardScaler``.  If *None*, raw
        (log-transformed) features are returned — useful during training
        when the scaler hasn't been fitted yet.

    Returns
    -------
    numpy.ndarray of shape ``(len(flows), len(ALL_FEATURE_NAMES))``.
    """
    df = flow_records_to_dataframe(flows)
    df = apply_log_transform(df)
    X = df.values.astype(np.float64)

    if scaler is not None:
        X = scaler.transform(X)

    return X
