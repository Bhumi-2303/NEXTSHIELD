"""Phishing module API routes."""

from fastapi import APIRouter

from ...schemas.phishing import PhishingScanResult

router = APIRouter(prefix="/phishing", tags=["Phishing Detection"])


@router.post("/scan", response_model=PhishingScanResult)
async def scan_email():
    """Analyse an email for phishing indicators.

    TODO: accept email payload, extract features, run model, return result.
    """
    raise NotImplementedError("Phishing scan not yet implemented.")
