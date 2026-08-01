"""Playbook module API routes."""

from fastapi import APIRouter

from ...schemas.playbook import Playbook

router = APIRouter(prefix="/playbooks", tags=["Incident Response Playbooks"])


@router.get("/", response_model=list[Playbook])
async def list_playbooks():
    """Return all available playbooks.

    TODO: load from JSON/DB.
    """
    raise NotImplementedError("Playbook listing not yet implemented.")


@router.get("/{playbook_id}", response_model=Playbook)
async def get_playbook(playbook_id: str):
    """Retrieve a single playbook by ID.

    TODO: look up by ID.
    """
    raise NotImplementedError("Playbook retrieval not yet implemented.")
