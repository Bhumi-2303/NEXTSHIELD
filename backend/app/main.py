"""NEXTSHIELD — FastAPI application entry point.

Run with:
    uvicorn app.main:app --reload --port 8000
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import api_router
from .core.config import settings
from .core.logging import get_logger

logger = get_logger("main")

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Explainable, actionable cybersecurity threat detection platform. "
        "Covers phishing classification, network anomaly detection, and "
        "guided incident-response playbooks — all mapped to MITRE ATT&CK."
    ),
)

# ---------------------------------------------------------------------------
# CORS — allow the Next.js frontend on localhost:3000
# ---------------------------------------------------------------------------
origins = [origin.strip() for origin in settings.FRONTEND_ORIGIN.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "Accept"],
)

# ---------------------------------------------------------------------------
# Register module routers
# ---------------------------------------------------------------------------
app.include_router(api_router)


# ---------------------------------------------------------------------------
# Health check & Root
# ---------------------------------------------------------------------------
@app.get("/", tags=["System"])
async def root():
    """Root endpoint for deployment verification."""
    return {
        "status": "healthy",
        "message": "NEXTSHIELD Backend Running",
        "docs": "/docs"
    }

@app.get("/health", tags=["System"])
async def health_check():
    """Liveness probe."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


@app.on_event("startup")
async def on_startup():
    logger.info("%s v%s starting up", settings.APP_NAME, settings.APP_VERSION)
