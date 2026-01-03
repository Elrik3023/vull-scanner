"""FastAPI application for VULL Scanner API."""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from vull_scanner.api.routes import health_router, scans_router, auth_router
from vull_scanner.api.models.responses import ErrorResponse
from vull_scanner.utils.validation import ValidationError
from vull_scanner.api.metrics import MetricsMiddleware, metrics_endpoint
from vull_scanner.api.rate_limiter import RateLimitMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown events."""
    # Startup
    # TODO: Initialize database connection pool
    # TODO: Initialize Redis connection for Celery
    # TODO: Initialize logging

    yield

    # Shutdown
    # TODO: Close database connections
    # TODO: Close Redis connections
    # TODO: Cleanup resources


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application instance.
    """
    app = FastAPI(
        title="VULL Scanner API",
        description="""
## Vulnerability Scanner API

A REST API for managing vulnerability scans against web applications.

### Features
- **Async Scanning**: Submit scans and retrieve results asynchronously
- **Multiple Vulnerability Types**: Detects credentials, SQL injection, exposed endpoints
- **Technology Detection**: Identifies CMS, frameworks, and server software
- **Subdomain Discovery**: Enumerates subdomains for additional attack surface

### Authentication
API key authentication required for all scan endpoints.
Include your API key in the `X-API-Key` header.

### Rate Limits
- 100 scans per day per API key
- 10 concurrent scans per API key
        """,
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add rate limiting middleware
    app.add_middleware(RateLimitMiddleware)

    # Add metrics middleware
    app.add_middleware(MetricsMiddleware)

    # Register exception handlers
    @app.exception_handler(ValidationError)
    async def validation_error_handler(request: Request, exc: ValidationError):
        """Handle validation errors from our validation module."""
        return JSONResponse(
            status_code=400,
            content={
                "error": "validation_error",
                "message": str(exc),
            }
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        """Handle unexpected exceptions."""
        # Log the error for debugging
        import logging
        logging.getLogger("vull_scanner.api").exception(f"Unhandled exception: {exc}")

        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "message": "An internal error occurred. Please try again later.",
            }
        )

    # Register routers
    app.include_router(health_router)
    app.include_router(scans_router, prefix="/api/v1")
    app.include_router(auth_router, prefix="/api/v1")

    # Metrics endpoint
    app.add_route("/metrics", metrics_endpoint, methods=["GET"])

    # Root endpoint
    @app.get("/", include_in_schema=False)
    async def root():
        """Root endpoint redirecting to documentation."""
        return {
            "name": "VULL Scanner API",
            "version": "0.1.0",
            "docs": "/docs",
            "health": "/health",
        }

    return app


# Create the application instance
app = create_app()


# Entry point for running with uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "vull_scanner.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
