"""Network anomaly detection module.

Responsible for:
- Ingesting NetFlow / PCAP feature vectors
- Hybrid detection: Isolation Forest (unsupervised) + XGBoost (supervised)
- Combining model outputs into a weighted anomaly score
- Flagging zero-day candidates (IForest anomalous + low supervised confidence)
- Mapping predictions to MITRE ATT&CK technique IDs
- Producing NetworkAnomalyResult alerts
"""
