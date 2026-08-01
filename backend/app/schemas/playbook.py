"""Playbook — incident response runbook linked to MITRE ATT&CK techniques."""

from __future__ import annotations

from pydantic import BaseModel, Field

from ..core.constants import MITRETechnique, SeverityLevel


class PlaybookStep(BaseModel):
    """A single step in an incident-response playbook."""

    action: str = Field(..., description="Short imperative action label.")
    description: str = Field(
        ..., description="Detailed instructions for this step."
    )
    automatable: bool = Field(
        False, description="Whether this step can be executed automatically."
    )


class Playbook(BaseModel):
    """A complete incident-response playbook."""

    id: str = Field(..., description="Unique playbook identifier, e.g. 'PB-T1566-001'.")
    mitre_technique_id: MITRETechnique = Field(
        ..., description="MITRE technique this playbook addresses."
    )
    title: str = Field(..., description="Human-readable playbook title.")
    severity_threshold: SeverityLevel = Field(
        ..., description="Minimum severity that triggers this playbook."
    )
    steps: list[PlaybookStep] = Field(
        ..., description="Ordered list of response steps."
    )
    estimated_response_time_minutes: int = Field(
        ..., ge=0, description="Estimated time to complete all steps."
    )
