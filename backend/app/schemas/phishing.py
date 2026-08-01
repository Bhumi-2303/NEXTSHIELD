"""PhishingScanResult — ThreatAlert subtype for phishing detections."""

from __future__ import annotations

from typing import Optional

from pydantic import Field

from .threat_alert import ThreatAlert


class PhishingScanResult(ThreatAlert):
    """Extended alert with email/phishing-specific features."""

    source_module: str = "phishing"  # locked default

    sender_domain: str = Field(
        ..., description="Domain part of the sender's email address."
    )
    domain_age_days: Optional[int] = Field(
        None, description="Age of sender domain in days (via WHOIS)."
    )
    spf_pass: bool = Field(
        False, description="Whether the email passed SPF validation."
    )
    dkim_pass: bool = Field(
        False, description="Whether the email passed DKIM validation."
    )
    dmarc_pass: bool = Field(
        False, description="Whether the email passed DMARC validation."
    )
    urgency_score: float = Field(
        0.0,
        ge=0.0,
        le=1.0,
        description="NLP-derived urgency score from subject/body.",
    )
    url_reputation_flags: list[str] = Field(
        default_factory=list,
        description="Flags from URL reputation checks, e.g. ['newly_registered', 'known_phish_domain'].",
    )
