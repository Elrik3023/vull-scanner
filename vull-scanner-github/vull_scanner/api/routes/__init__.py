"""API route modules."""

from vull_scanner.api.routes.health import router as health_router
from vull_scanner.api.routes.scans import router as scans_router
from vull_scanner.api.routes.auth import router as auth_router

__all__ = ["health_router", "scans_router", "auth_router"]
