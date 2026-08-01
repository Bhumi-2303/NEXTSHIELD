"""MITRE ATT&CK mapping and severity classification for network attacks.

Maps supervised model class labels (CICIDS2017 attack types) to MITRE
ATT&CK technique IDs and severity levels.
"""

from __future__ import annotations

from typing import Optional

from ...core.constants import MITRETechnique, SeverityLevel


# ── Attack type → MITRE ATT&CK technique ─────────────────────────────────
# Keys are the label-encoded class names from the CICIDS2017 / CICIoT2023
# datasets.  Values are the best-match MITRE technique enum members.

ATTACK_TYPE_TO_MITRE: dict[str, Optional[MITRETechnique]] = {
    # Benign traffic — no technique
    "BENIGN": None,

    # Botnet C2
    "Bot": MITRETechnique.T1071,

    # Distributed Denial of Service
    "DDoS": MITRETechnique.T1498,

    # Endpoint Denial of Service variants
    "DoS Hulk": MITRETechnique.T1499,
    "DoS GoldenEye": MITRETechnique.T1499,
    "DoS Slowhttptest": MITRETechnique.T1499,
    "DoS slowloris": MITRETechnique.T1499,

    # Brute-force authentication attacks
    "FTP-Patator": MITRETechnique.T1110,
    "SSH-Patator": MITRETechnique.T1110,

    # Exploits
    "Heartbleed": MITRETechnique.T1190,

    # Infiltration / exfiltration
    "Infiltration": MITRETechnique.T1048,

    # Reconnaissance
    "PortScan": MITRETechnique.T1595,

    # Web application attacks
    "Web Attack \u2013 Brute Force": MITRETechnique.T1110,
    "Web Attack \u2013 XSS": MITRETechnique.T1190,
    "Web Attack \u2013 Sql Injection": MITRETechnique.T1190,
}


# ── Attack type → severity level ──────────────────────────────────────────

ATTACK_TYPE_TO_SEVERITY: dict[str, SeverityLevel] = {
    "BENIGN": SeverityLevel.LOW,

    "Bot": SeverityLevel.HIGH,
    "DDoS": SeverityLevel.CRITICAL,

    "DoS Hulk": SeverityLevel.HIGH,
    "DoS GoldenEye": SeverityLevel.HIGH,
    "DoS Slowhttptest": SeverityLevel.MEDIUM,
    "DoS slowloris": SeverityLevel.MEDIUM,

    "FTP-Patator": SeverityLevel.HIGH,
    "SSH-Patator": SeverityLevel.HIGH,

    "Heartbleed": SeverityLevel.CRITICAL,
    "Infiltration": SeverityLevel.CRITICAL,
    "PortScan": SeverityLevel.MEDIUM,

    "Web Attack \u2013 Brute Force": SeverityLevel.HIGH,
    "Web Attack \u2013 XSS": SeverityLevel.HIGH,
    "Web Attack \u2013 Sql Injection": SeverityLevel.CRITICAL,
}


# ── Default fallback for unknown labels ───────────────────────────────────

DEFAULT_MITRE = MITRETechnique.T1046  # Network Service Discovery (generic)
DEFAULT_SEVERITY = SeverityLevel.MEDIUM


def lookup_mitre(attack_type: str) -> MITRETechnique:
    """Return the MITRE technique for an attack label, with fallback."""
    return ATTACK_TYPE_TO_MITRE.get(attack_type) or DEFAULT_MITRE


def lookup_severity(attack_type: str) -> SeverityLevel:
    """Return the severity for an attack label, with fallback."""
    return ATTACK_TYPE_TO_SEVERITY.get(attack_type, DEFAULT_SEVERITY)
