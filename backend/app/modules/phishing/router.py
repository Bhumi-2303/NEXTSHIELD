"""Phishing module API routes."""

from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException

from ...schemas.phishing import PhishingScanResult
from . import model as phishing_model

router = APIRouter(prefix="/phishing", tags=["Phishing Detection"])


# ---------------------------------------------------------------------------
# Request body schema (module-local, not shared)
# ---------------------------------------------------------------------------

class EmailPayload(BaseModel):
    """Raw email payload accepted by the ``/scan`` endpoint."""

    sender: str = Field(
        ...,
        description="Sender email address, e.g. 'alert@secure-bank.xyz'.",
        examples=["noreply@paypa1.com"],
    )
    subject: str = Field(
        ...,
        description="Email subject line.",
        examples=["URGENT: Your account has been compromised!"],
    )
    body: str = Field(
        ...,
        description="Plain-text or HTML email body.",
        examples=[
            "Dear Customer, We detected unauthorized access to your account. "
            "Click here to verify: http://paypa1-secure.xyz/verify"
        ],
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Raw email headers as key-value pairs.  At minimum, include "
            "'Authentication-Results' for SPF/DKIM/DMARC parsing."
        ),
    )
    urls: list[str] | None = Field(
        None,
        description=(
            "Pre-extracted URLs from the email.  If omitted, URLs are "
            "automatically extracted from the body text."
        ),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/scan",
    response_model=PhishingScanResult,
    summary="Scan an email for phishing indicators",
    response_description="Phishing analysis result with confidence score, "
                         "SHAP explanation, and MITRE ATT&CK mapping.",
)
async def scan_email(payload: EmailPayload) -> PhishingScanResult:
    """Analyse a raw email for phishing indicators.

    Extracts text, sender, and URL features, runs them through a LightGBM
    classifier (or rule-based fallback), and returns a fully populated
    ``PhishingScanResult`` mapped to MITRE ATT&CK T1566 (Phishing).
    """
    try:
        result = phishing_model.predict(
            sender=payload.sender,
            subject=payload.subject,
            body=payload.body,
            headers=payload.headers,
            urls=payload.urls,
        )
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Phishing scan failed: {exc}",
        ) from exc
