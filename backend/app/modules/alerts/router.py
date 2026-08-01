"""Alerts module API routes."""

import random
import secrets
import uuid
import pandas as pd
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter

from ...schemas.threat_alert import ThreatAlert
from ...schemas.flow_request import FlowRecord
from ..phishing import model as phishing_model
from ..anomaly.detector import detector as anomaly_detector

router = APIRouter(prefix="/alerts", tags=["Alerts Feed"])

# Global state to hold live feed
_live_alerts: list[ThreatAlert] = []
_dataset_phish_df = None
_dataset_anomaly_df = None

def _load_datasets():
    global _dataset_phish_df, _dataset_anomaly_df
    if _dataset_phish_df is None:
        phish_csv = Path("../data/phishing/dataset.csv")
        if phish_csv.exists():
            _dataset_phish_df = pd.read_csv(phish_csv)
    if _dataset_anomaly_df is None:
        anomaly_csv = Path("../data/CICIDS2017/Wednesday-workingHours.pcap_ISCX.csv")
        if anomaly_csv.exists():
            _dataset_anomaly_df = pd.read_csv(anomaly_csv)
            _dataset_anomaly_df.columns = _dataset_anomaly_df.columns.str.strip()

@router.get("", response_model=list[ThreatAlert])
async def get_live_alerts():
    """Return the live feed of alerts, simulating real-time traffic."""
    global _live_alerts, _dataset_phish_df, _dataset_anomaly_df
    
    _load_datasets()
    
    # Decide which type of alert to generate (50/50 chance if both datasets available)
    can_phish = _dataset_phish_df is not None and not _dataset_phish_df.empty
    can_anomaly = _dataset_anomaly_df is not None and not _dataset_anomaly_df.empty
    
    if not can_phish and not can_anomaly:
        return _live_alerts
        
    choice = "phishing"
    if can_phish and can_anomaly:
        choice = random.choice(["phishing", "anomaly"])
    elif can_anomaly:
        choice = "anomaly"
        
    if choice == "phishing":
        row = _dataset_phish_df.sample(n=1).iloc[0]
        text = str(row["text"])
        lines = text.strip().split("\n", 1)
        subject = lines[0][:200] if lines else "No Subject"
        body = lines[1] if len(lines) > 1 else text
        
        scan_result = phishing_model.predict(
            sender="unknown@example.com",
            subject=subject,
            body=body,
        )
        
        alert = ThreatAlert(
            id=str(uuid.uuid4()),
            source_module="phishing",
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity=scan_result.severity,
            mitre_technique_id=scan_result.mitre_technique_id,
            confidence_score=scan_result.confidence_score,
            explanation=scan_result.explanation,
            raw_payload={
                "sender": "unknown@example.com",
                "subject": subject,
                "body_preview": body[:100] + "..." if len(body) > 100 else body,
                "actual_label": int(row.get("label", -1))
            }
        )
        _live_alerts.insert(0, alert)
        
    elif choice == "anomaly":
        row = _dataset_anomaly_df.sample(n=1).iloc[0]
        # Build FlowRecord
        # Try to map columns gracefully or fallback to 0/empty
        
        # We need a FlowRecord
        flow = FlowRecord(
            src_ip="192.168.1." + str(secrets.randbelow(241) + 10),
            dst_ip="10.0.0." + str(secrets.randbelow(241) + 10),
            src_port=int(row.get("Source Port", row.get("Src Port", secrets.randbelow(64512) + 1024))),
            dst_port=int(row.get("Destination Port", row.get("Dst Port", 80))),
            protocol=str(row.get("Protocol", "TCP")),
            flow_duration=float(row.get("Flow Duration", row.get("flow_duration", 100.0))),
            fwd_packets=int(row.get("Total Fwd Packets", row.get("fwd_packets", 5))),
            bwd_packets=int(row.get("Total Backward Packets", row.get("bwd_packets", 5))),
            fwd_bytes=int(row.get("Total Length of Fwd Packets", row.get("fwd_bytes", 500))),
            bwd_bytes=int(row.get("Total Length of Bwd Packets", row.get("bwd_bytes", 500))),
            fin_flag_count=int(row.get("FIN Flag Count", 0)),
            syn_flag_count=int(row.get("SYN Flag Count", 0)),
            rst_flag_count=int(row.get("RST Flag Count", 0)),
            psh_flag_count=int(row.get("PSH Flag Count", 0)),
            ack_flag_count=int(row.get("ACK Flag Count", 0)),
            urg_flag_count=int(row.get("URG Flag Count", 0)),
            flow_iat_mean=float(row.get("Flow IAT Mean", 0.0)),
            flow_iat_std=float(row.get("Flow IAT Std", 0.0)),
            flow_iat_max=float(row.get("Flow IAT Max", 0.0)),
            flow_iat_min=float(row.get("Flow IAT Min", 0.0)),
        )
        
        results = anomaly_detector.predict_batch([flow])
        if results:
            res = results[0]
            # Override ID and timestamp for the live feed
            res.id = uuid.uuid4()
            res.timestamp = datetime.now(timezone.utc)
            
            # Add true label from dataset into raw_payload for visibility
            res.raw_payload = {
                "actual_label": str(row.get("Label", "UNKNOWN"))
            }
            
            _live_alerts.insert(0, res)

    # Keep only the last 20 alerts
    _live_alerts = _live_alerts[:20]
        
    return _live_alerts
