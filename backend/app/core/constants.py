"""Shared constants: MITRE ATT&CK technique IDs and severity levels."""

from enum import Enum


class MITRETechnique(str, Enum):
    """MITRE ATT&CK technique identifiers used across NEXTSHIELD.

    Reference: https://attack.mitre.org/techniques/enterprise/
    Add new techniques here as modules expand coverage.
    """

    T1566 = "T1566"  # Phishing
    T1071 = "T1071"  # Application Layer Protocol (C2)
    T1046 = "T1046"  # Network Service Discovery
    T1078 = "T1078"  # Valid Accounts
    T1499 = "T1499"  # Endpoint Denial of Service
    T1190 = "T1190"  # Exploit Public-Facing Application
    T1110 = "T1110"  # Brute Force
    T1498 = "T1498"  # Network Denial of Service
    T1048 = "T1048"  # Exfiltration Over Alternative Protocol
    T1595 = "T1595"  # Active Scanning

    @property
    def display_name(self) -> str:
        _names = {
            "T1566": "Phishing",
            "T1071": "Application Layer Protocol (C2)",
            "T1046": "Network Service Discovery",
            "T1078": "Valid Accounts",
            "T1499": "Endpoint Denial of Service",
            "T1190": "Exploit Public-Facing Application",
            "T1110": "Brute Force",
            "T1498": "Network Denial of Service",
            "T1048": "Exfiltration Over Alternative Protocol",
            "T1595": "Active Scanning",
        }
        return _names[self.value]


class SeverityLevel(str, Enum):
    """Alert severity, used in ThreatAlert and Playbook models."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
