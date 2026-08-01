"""Shared Pydantic contracts for NEXTSHIELD.

Every module (phishing, anomaly, playbook, explainability) imports from
here so that API responses are consistent and type-safe.
"""

from .threat_alert import ThreatAlert
from .shap_explanation import SHAPExplanation, SHAPFeature
from .playbook import Playbook, PlaybookStep
from .phishing import PhishingScanResult
from .anomaly import NetworkAnomalyResult
from .flow_request import FlowRecord, FlowBatchRequest

__all__ = [
    "ThreatAlert",
    "SHAPExplanation",
    "SHAPFeature",
    "Playbook",
    "PlaybookStep",
    "PhishingScanResult",
    "NetworkAnomalyResult",
    "FlowRecord",
    "FlowBatchRequest",
]
