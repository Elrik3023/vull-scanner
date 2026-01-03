"""Health check endpoints."""

from fastapi import APIRouter, Depends
from datetime import datetime

from vull_scanner.api.models.responses import HealthResponse

router = APIRouter(prefix="/health", tags=["Health"])


@router.get(
    "",
    response_model=HealthResponse,
    summary="Health check",
    description="Check if the API service is running and healthy",
)
async def health_check() -> HealthResponse:
    """Basic health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        timestamp=datetime.utcnow(),
        checks={
            "api": True,
        }
    )


@router.get(
    "/ready",
    response_model=HealthResponse,
    summary="Readiness check",
    description="Check if the service is ready to accept requests (all dependencies available)",
)
async def readiness_check() -> HealthResponse:
    """
    Readiness check - verifies all dependencies are available.

    Used by Kubernetes/container orchestration for readiness probes.
    """
    checks = {
        "api": True,
        "database": False,  # Will be True when DB is set up
        "redis": False,     # Will be True when Redis is set up
    }

    # TODO: Add actual database and Redis connectivity checks
    # For now, we just check if we can import the required modules
    try:
        import sqlalchemy
        checks["database"] = True  # Placeholder - will check actual connection
    except ImportError:
        pass

    try:
        import redis
        checks["redis"] = True  # Placeholder - will check actual connection
    except ImportError:
        pass

    all_healthy = all(checks.values())

    return HealthResponse(
        status="ready" if all_healthy else "degraded",
        version="0.1.0",
        timestamp=datetime.utcnow(),
        checks=checks
    )


@router.get(
    "/live",
    response_model=HealthResponse,
    summary="Liveness check",
    description="Check if the service process is alive",
)
async def liveness_check() -> HealthResponse:
    """
    Liveness check - verifies the process is running.

    Used by Kubernetes/container orchestration for liveness probes.
    """
    return HealthResponse(
        status="alive",
        version="0.1.0",
        timestamp=datetime.utcnow(),
        checks={"process": True}
    )
