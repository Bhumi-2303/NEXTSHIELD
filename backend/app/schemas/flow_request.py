"""FlowRecord / FlowBatchRequest — input schemas for anomaly analysis."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FlowRecord(BaseModel):
    """A single network flow record submitted for anomaly analysis.

    Field names align with CICIDS2017 / CICFlowMeter conventions so
    that raw CSV rows can be posted with minimal transformation.
    """

    src_ip: str = Field(..., description="Source IP address.")
    dst_ip: str = Field(..., description="Destination IP address.")
    src_port: int = Field(..., ge=0, le=65535, description="Source port.")
    dst_port: int = Field(..., ge=0, le=65535, description="Destination port.")
    protocol: str = Field(
        ..., description="Network protocol (TCP, UDP, ICMP, etc.)."
    )
    flow_duration: float = Field(
        ..., ge=0.0, description="Flow duration in seconds."
    )
    fwd_packets: int = Field(..., ge=0, description="Forward packet count.")
    bwd_packets: int = Field(..., ge=0, description="Backward packet count.")
    fwd_bytes: int = Field(..., ge=0, description="Forward byte count.")
    bwd_bytes: int = Field(..., ge=0, description="Backward byte count.")

    # TCP flag counts
    fin_flag_count: int = Field(0, ge=0, description="FIN flag count.")
    syn_flag_count: int = Field(0, ge=0, description="SYN flag count.")
    rst_flag_count: int = Field(0, ge=0, description="RST flag count.")
    psh_flag_count: int = Field(0, ge=0, description="PSH flag count.")
    ack_flag_count: int = Field(0, ge=0, description="ACK flag count.")
    urg_flag_count: int = Field(0, ge=0, description="URG flag count.")

    # Inter-arrival time statistics
    flow_iat_mean: float = Field(0.0, ge=0.0, description="Mean inter-arrival time (seconds).")
    flow_iat_std: float = Field(0.0, ge=0.0, description="Std-dev of inter-arrival time.")
    flow_iat_max: float = Field(0.0, ge=0.0, description="Max inter-arrival time (seconds).")
    flow_iat_min: float = Field(0.0, ge=0.0, description="Min inter-arrival time (seconds).")


class FlowBatchRequest(BaseModel):
    """Batch of flow records for bulk anomaly analysis."""

    flows: list[FlowRecord] = Field(
        ..., min_length=1, description="One or more flow records to analyse."
    )
