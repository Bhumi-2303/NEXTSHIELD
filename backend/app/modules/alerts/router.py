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
    
    can_phish = _dataset_phish_df is not None and not _dataset_phish_df.empty
    can_anomaly = _dataset_anomaly_df is not None and not _dataset_anomaly_df.empty
    
    # Randomly pick a module. Even if datasets are missing, we fallback to synthetic data.
    choice = random.choice(["phishing", "anomaly"])
        
    if choice == "phishing":
        if can_phish:
            row = _dataset_phish_df.sample(n=1).iloc[0]
            text = str(row["text"])
            lines = text.strip().split("\n", 1)
            subject = lines[0][:200] if lines else "No Subject"
            body = lines[1] if len(lines) > 1 else text
            label = int(row.get("label", -1))
        else:
            # Synthetic fallback
            is_attack = random.random() > 0.5
            if is_attack:
                subject = "URGENT: Your account will be suspended"
                body = "Please login here to verify your identity: http://suspicious-link.com"
                label = 1
            else:
                subject = "Meeting Notes - Q3 Planning"
                body = "Hi team, attached are the notes from our Q3 planning session."
                label = 0
        
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
                "actual_label": label
            }
        )
        _live_alerts.insert(0, alert)
        
    elif choice == "anomaly":
        if can_anomaly:
            row = _dataset_anomaly_df.sample(n=1).iloc[0]
            src_port = int(row.get("Source Port", row.get("Src Port", secrets.randbelow(64512) + 1024)))
            dst_port = int(row.get("Destination Port", row.get("Dst Port", 80)))
            protocol = str(row.get("Protocol", "TCP"))
            flow_duration = float(row.get("Flow Duration", row.get("flow_duration", 100.0)))
            fwd_packets = int(row.get("Total Fwd Packets", row.get("fwd_packets", 5)))
            bwd_packets = int(row.get("Total Backward Packets", row.get("bwd_packets", 5)))
            fwd_bytes = int(row.get("Total Length of Fwd Packets", row.get("fwd_bytes", 500)))
            bwd_bytes = int(row.get("Total Length of Bwd Packets", row.get("bwd_bytes", 500)))
            fin = int(row.get("FIN Flag Count", 0))
            syn = int(row.get("SYN Flag Count", 0))
            rst = int(row.get("RST Flag Count", 0))
            psh = int(row.get("PSH Flag Count", 0))
            ack = int(row.get("ACK Flag Count", 0))
            urg = int(row.get("URG Flag Count", 0))
            flow_iat_mean = float(row.get("Flow IAT Mean", 0.0))
            flow_iat_std = float(row.get("Flow IAT Std", 0.0))
            flow_iat_max = float(row.get("Flow IAT Max", 0.0))
            flow_iat_min = float(row.get("Flow IAT Min", 0.0))
            actual_label = str(row.get("Label", "UNKNOWN"))
        else:
            is_attack = random.random() > 0.5
            src_port = secrets.randbelow(64512) + 1024
            dst_port = 80 if not is_attack else 4444
            protocol = "TCP"
            flow_duration = 100.0 if not is_attack else 5000.0
            fwd_packets = 5 if not is_attack else 100
            bwd_packets = 5 if not is_attack else 100
            fwd_bytes = 500 if not is_attack else 50000
            bwd_bytes = 500 if not is_attack else 50000
            fin = 0
            syn = 1
            rst = 0
            psh = 0
            ack = 1
            urg = 0
            flow_iat_mean = 10.0
            flow_iat_std = 2.0
            flow_iat_max = 20.0
            flow_iat_min = 1.0
            actual_label = "BENIGN" if not is_attack else "PortScan"
            
        flow = FlowRecord(
            src_ip="192.168.1." + str(secrets.randbelow(241) + 10),
            dst_ip="10.0.0." + str(secrets.randbelow(241) + 10),
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            flow_duration=flow_duration,
            fwd_packets=fwd_packets,
            bwd_packets=bwd_packets,
            fwd_bytes=fwd_bytes,
            bwd_bytes=bwd_bytes,
            fin_flag_count=fin,
            syn_flag_count=syn,
            rst_flag_count=rst,
            psh_flag_count=psh,
            ack_flag_count=ack,
            urg_flag_count=urg,
            flow_iat_mean=flow_iat_mean,
            flow_iat_std=flow_iat_std,
            flow_iat_max=flow_iat_max,
            flow_iat_min=flow_iat_min,
        )
        
        results = anomaly_detector.predict_batch([flow])
        if results:
            res = results[0]
            # Override ID and timestamp for the live feed
            res.id = str(uuid.uuid4())
            res.timestamp = datetime.now(timezone.utc).isoformat()
            
            # Add true label from dataset into raw_payload for visibility
            res.raw_payload = {
                "actual_label": actual_label
            }
            
            _live_alerts.insert(0, res)

    # Keep only the last 20 alerts
    _live_alerts = _live_alerts[:20]
        
    return _live_alerts

