"""NetworkAnomalyResult — ThreatAlert subtype for network anomaly detections."""

from __future__ import annotations

from pydantic import Field

from .threat_alert import ThreatAlert


class NetworkAnomalyResult(ThreatAlert):
    """Extended alert with network-flow-specific features."""

    source_module: str = "anomaly"  # locked default

    src_ip: str = Field(..., description="Source IP address.")
    dst_ip: str = Field(..., description="Destination IP address.")
    protocol: str = Field(
        ..., description="Network protocol (TCP, UDP, ICMP, etc.)."
    )
    flow_duration: float = Field(
        ..., ge=0.0, description="Flow duration in seconds."
    )
    anomaly_score: float = Field(
        ..., ge=0.0, le=1.0, description="Isolation-forest / autoencoder anomaly score."
    )
    is_zero_day_candidate: bool = Field(
        False,
        description="True if the anomaly pattern has no known signature match.",
    )
