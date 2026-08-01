"""Playbook module API routes."""

from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException

from ...core.constants import MITRETechnique
from ...schemas.playbook import Playbook
from . import engine


router = APIRouter(prefix="/playbooks", tags=["Incident Response Playbooks"])


# ---------------------------------------------------------------------------
# Request schemas (module-local)
# ---------------------------------------------------------------------------

class SimulateRequest(BaseModel):
    """Request body for the simulate endpoint."""

    alert_id: str | None = Field(
        None,
        description="ID of the alert to look up for automatic playbook selection. "
                    "Mutually exclusive with playbook_id.",
    )
    playbook_id: str | None = Field(
        None,
        description="Explicit playbook ID to simulate. "
                    "Mutually exclusive with alert_id.",
    )
    mitre_technique_id: MITRETechnique | None = Field(
        None,
        description="MITRE technique ID for playbook lookup (used with alert_id "
                    "or standalone when no alert_id is available).",
    )
    severity: str | None = Field(
        None,
        description="Alert severity for playbook selection (low|medium|high|critical). "
                    "Used when mitre_technique_id is provided without alert_id.",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/",
    response_model=list[Playbook],
    summary="List all playbooks",
)
async def list_playbooks() -> list[Playbook]:
    """Return every playbook in the library."""
    return engine.get_all_playbooks()


@router.get(
    "/by-technique/{mitre_technique_id}",
    response_model=list[Playbook],
    summary="Get playbooks by MITRE technique",
)
async def get_playbooks_by_technique(
    mitre_technique_id: MITRETechnique,
) -> list[Playbook]:
    """Return all playbooks that address a specific MITRE ATT&CK technique."""
    playbooks = engine.get_playbooks_by_technique(mitre_technique_id)
    if not playbooks:
        raise HTTPException(
            status_code=404,
            detail=f"No playbooks found for technique {mitre_technique_id.value}",
        )
    return playbooks


@router.get(
    "/{playbook_id}",
    response_model=Playbook,
    summary="Get a playbook by ID",
)
async def get_playbook(playbook_id: str) -> Playbook:
    """Retrieve a single playbook by its ID."""
    pb = engine.get_playbook_by_id(playbook_id)
    if pb is None:
        raise HTTPException(
            status_code=404,
            detail=f"Playbook '{playbook_id}' not found",
        )
    return pb


@router.post(
    "/simulate",
    summary="Simulate playbook auto-response",
    response_description="Simulated response timeline with timestamps for each step.",
)
async def simulate_response(req: SimulateRequest) -> dict:
    """Simulate execution of a playbook's automatable steps.

    Provide either ``playbook_id`` for a specific playbook, or
    ``mitre_technique_id`` + ``severity`` to auto-select the best match.

    Returns a response timeline showing which steps were auto-executed
    (with mock timing) and which require human action.
    """
    playbook: Playbook | None = None

    # Option 1: explicit playbook ID
    if req.playbook_id:
        playbook = engine.get_playbook_by_id(req.playbook_id)
        if playbook is None:
            raise HTTPException(
                status_code=404,
                detail=f"Playbook '{req.playbook_id}' not found",
            )

    # Option 2: select by technique + severity
    elif req.mitre_technique_id:
        from ...core.constants import SeverityLevel
        from ...schemas.threat_alert import ThreatAlert

        severity = SeverityLevel(req.severity) if req.severity else SeverityLevel.MEDIUM

        # Build a minimal alert for playbook selection
        mock_alert = ThreatAlert(
            source_module="phishing" if req.mitre_technique_id == MITRETechnique.T1566 else "anomaly",
            severity=severity,
            mitre_technique_id=req.mitre_technique_id,
            confidence_score=0.8,
        )
        playbook = engine.select_playbook(mock_alert)
        if playbook is None:
            raise HTTPException(
                status_code=404,
                detail=f"No playbook matches technique={req.mitre_technique_id.value} "
                       f"at severity={severity.value}",
            )

    else:
        raise HTTPException(
            status_code=422,
            detail="Provide either 'playbook_id' or 'mitre_technique_id' (+ optional 'severity').",
        )

    return engine.simulate_response(playbook)
