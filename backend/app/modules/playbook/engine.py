"""Playbook engine — load, select, and simulate incident response playbooks.

Playbooks are stored as JSON in ``/data/playbooks/`` and loaded at import
time.  The engine provides:

- ``get_all_playbooks()`` — list every loaded playbook
- ``get_playbook_by_id(id)`` — exact lookup
- ``get_playbooks_by_technique(technique)`` — filter by MITRE ATT&CK ID
- ``select_playbook(alert)`` — best-match for a ThreatAlert
- ``simulate_response(playbook)`` — mock execution of automatable steps
"""

from __future__ import annotations

import json
import random
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from ...core.constants import MITRETechnique, SeverityLevel
from ...core.logging import get_logger
from ...schemas.playbook import Playbook
from ...schemas.threat_alert import ThreatAlert

logger = get_logger("playbook.engine")

# ---------------------------------------------------------------------------
# Severity ordering for comparison
# ---------------------------------------------------------------------------
_SEVERITY_ORDER: dict[SeverityLevel, int] = {
    SeverityLevel.LOW: 0,
    SeverityLevel.MEDIUM: 1,
    SeverityLevel.HIGH: 2,
    SeverityLevel.CRITICAL: 3,
}

# ---------------------------------------------------------------------------
# Playbook store (loaded once at import time)
# ---------------------------------------------------------------------------
_playbooks: dict[str, Playbook] = {}
_loaded: bool = False


def _find_playbook_data_dir() -> Path:
    """Locate the ``data/playbooks/`` directory relative to the project root."""
    # Walk up from this file to the repo root
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "data" / "playbooks"
        if candidate.is_dir():
            return candidate
    # Fallback: relative to cwd
    return Path("data/playbooks")


def load_playbooks(data_dir: Path | str | None = None) -> int:
    """Load all ``.json`` playbook files from *data_dir*.

    Each JSON file may contain a single playbook object or an array of
    playbook objects.  Returns the number of playbooks loaded.
    """
    global _playbooks, _loaded

    if data_dir is None:
        data_dir = _find_playbook_data_dir()
    data_dir = Path(data_dir)

    if not data_dir.exists():
        logger.warning("Playbook data directory not found: %s", data_dir)
        _loaded = True
        return 0

    count = 0
    for json_file in sorted(data_dir.glob("*.json")):
        try:
            with open(json_file, "r") as f:
                raw = json.load(f)

            items = raw if isinstance(raw, list) else [raw]
            for item in items:
                pb = Playbook(**item)
                _playbooks[pb.id] = pb
                count += 1
        except Exception as exc:
            logger.error("Failed to load playbook file %s: %s", json_file, exc)

    _loaded = True
    logger.info("Loaded %d playbooks from %s", count, data_dir)
    return count


def _ensure_loaded() -> None:
    """Lazy-load playbooks on first access."""
    if not _loaded:
        load_playbooks()


# ============================================================================
# Query functions
# ============================================================================

def get_all_playbooks() -> list[Playbook]:
    """Return all loaded playbooks."""
    _ensure_loaded()
    return list(_playbooks.values())


def get_playbook_by_id(playbook_id: str) -> Optional[Playbook]:
    """Look up a playbook by its ID (e.g. ``PB-T1566-001``)."""
    _ensure_loaded()
    return _playbooks.get(playbook_id)


def get_playbooks_by_technique(technique: MITRETechnique) -> list[Playbook]:
    """Return all playbooks that address a given MITRE ATT&CK technique."""
    _ensure_loaded()
    return [pb for pb in _playbooks.values()
            if pb.mitre_technique_id == technique]


# ============================================================================
# Selection logic
# ============================================================================

def select_playbook(alert: ThreatAlert) -> Optional[Playbook]:
    """Select the best-matching playbook for a given alert.

    Matching strategy:
      1. Filter playbooks by ``mitre_technique_id``
      2. Filter by ``severity_threshold`` ≤ alert severity
      3. Pick the one with the **highest** severity threshold that still
         qualifies (most specific match)
      4. Tie-break by playbook ID (deterministic)

    Returns ``None`` if no playbook matches.
    """
    _ensure_loaded()

    alert_severity_rank = _SEVERITY_ORDER.get(alert.severity, 0)
    candidates: list[Playbook] = []

    for pb in _playbooks.values():
        if pb.mitre_technique_id != alert.mitre_technique_id:
            continue
        threshold_rank = _SEVERITY_ORDER.get(pb.severity_threshold, 0)
        if threshold_rank <= alert_severity_rank:
            candidates.append(pb)

    if not candidates:
        return None

    # Pick the most specific (highest threshold that still qualifies)
    candidates.sort(
        key=lambda pb: (_SEVERITY_ORDER.get(pb.severity_threshold, 0), pb.id),
        reverse=True,
    )
    return candidates[0]


# ============================================================================
# Simulation engine
# ============================================================================

def simulate_response(playbook: Playbook) -> dict[str, Any]:
    """Simulate execution of a playbook for demo purposes.

    "Executes" each automatable step with a mock delay and success status.
    Manual steps are marked as ``pending_human_action``.

    Returns a response timeline dict suitable for API serialisation.
    """
    timeline: list[dict[str, Any]] = []
    cursor = datetime.utcnow()
    total_automated = 0
    total_manual = 0

    for i, step in enumerate(playbook.steps, start=1):
        entry: dict[str, Any] = {
            "step_number": i,
            "action": step.action,
            "automatable": step.automatable,
        }

        if step.automatable:
            # Simulate execution: random 1-8 second "processing" time
            exec_seconds = round(random.uniform(1.0, 8.0), 2)
            cursor += timedelta(seconds=exec_seconds)

            entry.update({
                "status": "completed",
                "executed_at": cursor.isoformat() + "Z",
                "duration_seconds": exec_seconds,
                "result": f"Auto-executed successfully: {step.action}",
            })
            total_automated += 1
            logger.info(
                "[SIM] Step %d auto-executed in %.2fs: %s",
                i, exec_seconds, step.action,
            )
        else:
            entry.update({
                "status": "pending_human_action",
                "executed_at": None,
                "duration_seconds": None,
                "result": f"Awaiting human action: {step.description[:100]}...",
            })
            total_manual += 1

        timeline.append(entry)

    return {
        "playbook_id": playbook.id,
        "playbook_title": playbook.title,
        "mitre_technique_id": playbook.mitre_technique_id.value,
        "simulation_started_at": datetime.utcnow().isoformat() + "Z",
        "total_steps": len(playbook.steps),
        "automated_steps_completed": total_automated,
        "manual_steps_pending": total_manual,
        "estimated_response_time_minutes": playbook.estimated_response_time_minutes,
        "timeline": timeline,
    }
