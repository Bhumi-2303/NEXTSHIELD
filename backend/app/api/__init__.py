"""API route registration.

This package collects routers from all modules and exposes a single
`api_router` for main.py to include.
"""

from fastapi import APIRouter

from ..modules.phishing.router import router as phishing_router
from ..modules.anomaly.router import router as anomaly_router
from ..modules.playbook.router import router as playbook_router
from ..modules.explainability.router import router as explainability_router
from ..modules.alerts.router import router as alerts_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(phishing_router)
api_router.include_router(anomaly_router)
api_router.include_router(playbook_router)
api_router.include_router(explainability_router)
api_router.include_router(alerts_router)
