"""
Offline training script for the anomaly detection models (Isolation Forest and XGBoost).

Usage:
    Run from the backend/ directory:
    python -m training.train_anomaly_models
"""

import os
import sys
import time
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import xgboost as xgb

sys.path.insert(0, '.')
from app.modules.anomaly.feature_engineering import (
    NUMERIC_FEATURES, PROTOCOL_CATEGORIES, ALL_FEATURE_NAMES,
    apply_log_transform, _encode_protocol
)

def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def generate_synthetic_data(num_samples=10000):
    log("Generating synthetic dataset for training/dev...")
    np.random.seed(42)
    
    labels = [
        "BENIGN", "DoS Hulk", "PortScan", "DDoS", "DoS GoldenEye", 
        "FTP-Patator", "SSH-Patator", "DoS slowloris", "DoS Slowhttptest", 
        "Bot", "Web Attack – Brute Force", "Web Attack – XSS", 
        "Heartbleed", "Infiltration"
    ]
    probs = [
        0.70, 0.08, 0.07, 0.05, 0.03, 
        0.02, 0.02, 0.01, 0.01, 
        0.005, 0.003, 0.001, 
        0.0005, 0.0005
    ]
    
    # Normalize probabilities to sum exactly to 1.0
    probs = np.array(probs) / np.sum(probs)
    
    data_labels = np.random.choice(labels, size=num_samples, p=probs)
    data = []
    
    for label in data_labels:
        # Base realistic defaults
        row = {
            'Label': label,
            'Flow Duration': np.random.exponential(100000),
            'Total Fwd Packets': np.random.poisson(5) + 1,
            'Total Backward Packets': np.random.poisson(5),
            'Total Length of Fwd Packets': np.random.exponential(500),
            'Total Length of Bwd Packets': np.random.exponential(500),
            'Fwd Packet Length Max': np.random.exponential(100),
            'Fwd Packet Length Min': np.random.exponential(10),
            'Fwd Packet Length Mean': np.random.exponential(50),
            'Bwd Packet Length Max': np.random.exponential(100),
            'Bwd Packet Length Min': np.random.exponential(10),
            'Bwd Packet Length Mean': np.random.exponential(50),
            'Flow Bytes/s': np.random.exponential(1000),
            'Flow Packets/s': np.random.exponential(100),
            'Flow IAT Mean': np.random.exponential(5000),
            'Flow IAT Std': np.random.exponential(1000),
            'Flow IAT Max': np.random.exponential(20000),
            'Flow IAT Min': np.random.exponential(100),
            'Fwd IAT Total': np.random.exponential(50000),
            'Bwd IAT Total': np.random.exponential(50000),
            'Fwd PSH Flags': np.random.binomial(1, 0.1),
            'Bwd PSH Flags': 0,
            'Fwd URG Flags': 0,
            'Bwd URG Flags': 0,
            'Fwd Header Length': np.random.poisson(100),
            'Bwd Header Length': np.random.poisson(100),
            'Fwd Packets/s': np.random.exponential(50),
            'Bwd Packets/s': np.random.exponential(50),
            'Min Packet Length': np.random.exponential(10),
            'Max Packet Length': np.random.exponential(200),
            'Packet Length Mean': np.random.exponential(80),
            'Packet Length Std': np.random.exponential(40),
            'Packet Length Variance': np.random.exponential(1600),
            'FIN Flag Count': np.random.binomial(1, 0.05),
            'SYN Flag Count': np.random.binomial(1, 0.1),
            'RST Flag Count': np.random.binomial(1, 0.05),
            'PSH Flag Count': np.random.binomial(1, 0.2),
            'ACK Flag Count': np.random.binomial(1, 0.5),
            'URG Flag Count': np.random.binomial(1, 0.05),
            'CWE Flag Count': 0,
            'ECE Flag Count': np.random.binomial(1, 0.01),
            'Down/Up Ratio': np.random.poisson(1),
            'Average Packet Size': np.random.exponential(90),
            'Avg Fwd Segment Size': np.random.exponential(50),
            'Avg Bwd Segment Size': np.random.exponential(50),
            'Fwd Header Length.1': np.random.poisson(100),
            'Subflow Fwd Packets': np.random.poisson(5),
            'Subflow Fwd Bytes': np.random.exponential(500),
            'Subflow Bwd Packets': np.random.poisson(5),
            'Subflow Bwd Bytes': np.random.exponential(500),
            'Init_Win_bytes_forward': np.random.randint(1000, 65535),
            'Init_Win_bytes_backward': np.random.randint(1000, 65535),
            'act_data_pkt_fwd': np.random.poisson(2),
            'min_seg_size_forward': 20,
            'Active Mean': np.random.exponential(1000),
            'Active Std': np.random.exponential(100),
            'Active Max': np.random.exponential(2000),
            'Active Min': np.random.exponential(100),
            'Idle Mean': np.random.exponential(10000),
            'Idle Std': np.random.exponential(1000),
            'Idle Max': np.random.exponential(20000),
            'Idle Min': np.random.exponential(1000),
            
            # Additional keys used by our feature extraction logic
            'Source Port': np.random.randint(1024, 65535),
            'Destination Port': np.random.randint(1, 1024) if np.random.random() > 0.5 else np.random.randint(1024, 65535),
            'Protocol': np.random.choice([6, 17, 1], p=[0.7, 0.25, 0.05])
        }
        
        # Adjust features based on attack type to give signal
        if "DoS" in label or "DDoS" in label:
            row['Total Fwd Packets'] += np.random.poisson(100)
            row['Total Backward Packets'] += np.random.poisson(10)
            row['Total Length of Fwd Packets'] += np.random.exponential(5000)
            row['Flow Packets/s'] += np.random.exponential(1000)
            row['Flow Bytes/s'] += np.random.exponential(10000)
        elif "PortScan" in label:
            row['Flow Duration'] = np.random.exponential(1000)
            row['Total Fwd Packets'] = np.random.poisson(1) + 1
            row['Total Backward Packets'] = 0
            row['SYN Flag Count'] = 1
        elif "Brute Force" in label:
            row['SYN Flag Count'] = 1
            row['Total Fwd Packets'] += np.random.poisson(20)
            row['Total Backward Packets'] += np.random.poisson(20)
            
        data.append(row)
        
    df = pd.DataFrame(data)
    return df

def feature_engineering(df):
    log("Starting feature engineering...")

    # ── Column mapping (CICIDS2017 style → our canonical names) ──────
    col_map = {
        'Flow Duration': 'flow_duration',
        'Total Fwd Packets': 'fwd_packets',
        'Total Fwd Packet': 'fwd_packets', # Alternative spelling
        'Total Backward Packets': 'bwd_packets',
        'Total Bwd packets': 'bwd_packets', # Alternative spelling
        'Total Length of Fwd Packets': 'fwd_bytes',
        'Total Length of Fwd Packet': 'fwd_bytes', # Alternative spelling
        'Total Length of Bwd Packets': 'bwd_bytes',
        'Total Length of Bwd Packet': 'bwd_bytes', # Alternative spelling
        'FIN Flag Count': 'fin_flag_count',
        'SYN Flag Count': 'syn_flag_count',
        'RST Flag Count': 'rst_flag_count',
        'PSH Flag Count': 'psh_flag_count',
        'ACK Flag Count': 'ack_flag_count',
        'URG Flag Count': 'urg_flag_count',
        'Flow IAT Mean': 'flow_iat_mean',
        'Flow IAT Std': 'flow_iat_std',
        'Flow IAT Max': 'flow_iat_max',
        'Flow IAT Min': 'flow_iat_min',
        'Source Port': 'src_port',
        'Src Port': 'src_port', # Alternative spelling
        'Destination Port': 'dst_port',
        'Dst Port': 'dst_port', # Alternative spelling
    }
    df_work = df.rename(columns=col_map)

    # ── One-hot encode protocol ──────────────────────────────────────
    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    for p in PROTOCOL_CATEGORIES:
        if 'protocol' in df_work.columns or 'Protocol' in df_work.columns:
            proto_col = df_work.get('protocol', df_work.get('Protocol', pd.Series(dtype=int)))
            df_work[f"protocol_{p}"] = proto_col.apply(
                lambda v: int(proto_map.get(int(v), str(v)).upper() == p)
                if isinstance(v, (int, float, np.integer))
                else int(str(v).upper() == p)
            )
        else:
            df_work[f"protocol_{p}"] = 0

    # ── Fill any missing feature columns with 0 ──────────────────────
    for feat in ALL_FEATURE_NAMES:
        if feat not in df_work.columns:
            df_work[feat] = 0.0

    # Select features in canonical order
    X = df_work[ALL_FEATURE_NAMES].copy().astype(float)

    # ── Apply log transform (same as inference pipeline) ─────────────
    X = apply_log_transform(X)

    y = df['Label']
    log(f"Feature matrix shape: {X.shape}, labels: {y.nunique()} classes")
    return X, y

def main():
    os.makedirs('models', exist_ok=True)
    
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
    data_path = os.path.join(project_root, 'data/network/cicids2017_wednesday.csv')
    
    if os.path.exists(data_path):
        log(f"Loading data from {data_path}")
        df = pd.read_csv(data_path)
    else:
        log(f"Data not found at {data_path}")
        df = generate_synthetic_data(10000)
        
    X, y = feature_engineering(df)
    
    # 1. Isolation Forest (Unsupervised - trained only on BENIGN)
    log("Training Isolation Forest on BENIGN traffic...")
    benign_mask = y == 'BENIGN'
    X_benign = X[benign_mask]
    
    iforest = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
    iforest.fit(X_benign)
    
    iforest_path = 'models/anomaly_iforest.joblib'
    joblib.dump(iforest, iforest_path)
    log(f"Saved Isolation Forest to {iforest_path}")
    
    # 2. StandardScaler
    log("Fitting StandardScaler on all data...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    scaler_path = 'models/anomaly_scaler.joblib'
    joblib.dump(scaler, scaler_path)
    log(f"Saved StandardScaler to {scaler_path}")
    
    # 3. Label Encoder
    log("Fitting LabelEncoder...")
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    le_path = 'models/anomaly_label_encoder.joblib'
    joblib.dump(le, le_path)
    log(f"Saved LabelEncoder to {le_path}")
    
    # Stratified split — fall back to non-stratified if any class has < 2 members
    from collections import Counter
    class_counts = Counter(y_encoded)
    can_stratify = all(c >= 2 for c in class_counts.values())
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y_encoded, test_size=0.2, random_state=42,
        stratify=y_encoded if can_stratify else None,
    )
    if not can_stratify:
        log("WARNING: Some classes have <2 members; using non-stratified split.")
    
    xgb_clf = xgb.XGBClassifier(
        n_estimators=200, 
        max_depth=6, 
        learning_rate=0.1, 
        use_label_encoder=False, 
        eval_metric='mlogloss', 
        random_state=42
    )
    
    xgb_clf.fit(X_train, y_train)
    
    xgb_path = 'models/anomaly_xgboost.joblib'
    joblib.dump(xgb_clf, xgb_path)
    log(f"Saved XGBoost Classifier to {xgb_path}")
    
    # 5. Evaluation Output
    log("Evaluating XGBoost model on test set...")
    y_pred = xgb_clf.predict(X_test)
    
    log("Classification Report:")
    report = classification_report(y_test, y_pred, target_names=le.inverse_transform(np.unique(y_test)))
    print(report)
    
    accuracy = accuracy_score(y_test, y_pred)
    log(f"Overall Accuracy: {accuracy:.4f}")
    
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y_test, y_pred)
    log(f"Confusion Matrix Shape: {cm.shape}")
    
    # Print per-class accuracy
    cm_diag = cm.diagonal()
    cm_sum = cm.sum(axis=1)
    # Avoid division by zero
    per_class_acc = np.divide(cm_diag, cm_sum, out=np.zeros_like(cm_diag, dtype=float), where=cm_sum!=0)
    
    log("Per-class Accuracy:")
    for cls_idx, acc in enumerate(per_class_acc):
        cls_name = le.inverse_transform([cls_idx])[0]
        print(f"  {cls_name}: {acc:.4f}")
        
    log("Training completed successfully.")

if __name__ == '__main__':
    main()
