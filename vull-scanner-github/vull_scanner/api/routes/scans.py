"""Scan management endpoints."""

import os
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Path, Depends, Request
from sqlalchemy.orm import Session

from vull_scanner.api.models.requests import ScanRequest
from vull_scanner.api.models.responses import (
    ScanResponse,
    ScanStatusResponse,
    ScanResultsResponse,
    ScanStatus,
    VulnerabilityResponse,
    VulnerabilitySeverity,
    VulnerabilityType,
    TechnologyResponse,
    ErrorResponse,
)
from vull_scanner.utils.validation import validate_target, ValidationError
from vull_scanner.db.database import get_db
from vull_scanner.db.repositories import ScanRepository
from vull_scanner.db import models as db_models
from vull_scanner.api.auth import get_current_api_key, check_scan_limits
from vull_scanner.api.rate_limiter import get_rate_limiter

router = APIRouter(prefix="/scans", tags=["Scans"])


def _get_scan_repo(db: Session = Depends(get_db)) -> ScanRepository:
    """Get scan repository instance."""
    return ScanRepository(db)


@router.post(
    "",
    response_model=ScanResponse,
    status_code=201,
    summary="Create a new scan",
    description="Submit a new vulnerability scan request for the specified target",
    responses={
        201: {"description": "Scan created successfully"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        422: {"description": "Validation error"},
    }
)
async def create_scan(
    scan_request: ScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    api_key: db_models.APIKey = Depends(get_current_api_key),
) -> ScanResponse:
    """
    Create a new vulnerability scan.

    The scan will be queued and executed asynchronously.
    Use the returned scan ID to check status and retrieve results.

    Requires authentication via X-API-Key header or Bearer token.
    """
    # Check all rate limits (daily, concurrent, per-key)
    check_scan_limits(api_key, request)

    # Validate target using our SSRF-protected validation
    try:
        validated_target = validate_target(
            scan_request.target,
            allow_private=scan_request.options.allow_private if scan_request.options else False
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=400,
            detail={"error": "validation_error", "message": str(e)}
        )

    # Create scan in database
    repo = ScanRepository(db)
    scan = repo.create(
        target=validated_target,
        options=scan_request.options.model_dump() if scan_request.options else {},
        callback_url=scan_request.callback_url,
        original_target=scan_request.target,
    )

    # Increment rate limiter counters
    rate_limiter = get_rate_limiter()
    rate_limiter.increment_scan_count(request, api_key.id)

    # Queue the scan for execution via Celery
    try:
        from vull_scanner.worker import execute_scan
        execute_scan.delay(scan.id)
    except Exception as e:
        # If Celery is not available, log warning but don't fail
        import logging
        logging.getLogger("vull_scanner.api").warning(
            f"Could not queue scan {scan.id}: {e}. Celery may not be running."
        )

    return ScanResponse(
        id=scan.id,
        target=validated_target,
        status=ScanStatus.PENDING,
        created_at=scan.created_at,
        message="Scan queued successfully"
    )


@router.get(
    "",
    response_model=list[ScanStatusResponse],
    summary="List all scans",
    description="Get a list of all scans with their current status",
)
async def list_scans(
    status: Optional[str] = Query(
        None,
        description="Filter by scan status (pending, running, completed, failed, cancelled)"
    ),
    limit: int = Query(
        50,
        ge=1,
        le=100,
        description="Maximum number of scans to return"
    ),
    offset: int = Query(
        0,
        ge=0,
        description="Number of scans to skip"
    ),
    db: Session = Depends(get_db),
    api_key: db_models.APIKey = Depends(get_current_api_key),
) -> list[ScanStatusResponse]:
    """List all scans with optional filtering."""
    repo = ScanRepository(db)

    # Convert string status to enum if provided
    db_status = None
    if status:
        try:
            db_status = db_models.ScanStatus(status)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_status", "message": f"Invalid status: {status}"}
            )

    scans = repo.list_all(status=db_status, limit=limit, offset=offset)

    return [
        ScanStatusResponse(
            id=s.id,
            target=s.target,
            status=ScanStatus(s.status.value),
            progress=s.progress,
            current_phase=s.current_phase,
            created_at=s.created_at,
            started_at=s.started_at,
            completed_at=s.completed_at,
            error_message=s.error_message,
            vulnerabilities_found=len(s.vulnerabilities) if s.vulnerabilities else 0
        )
        for s in scans
    ]


@router.get(
    "/{scan_id}",
    response_model=ScanStatusResponse,
    summary="Get scan status",
    description="Get the current status of a specific scan",
    responses={
        404: {"model": ErrorResponse, "description": "Scan not found"},
    }
)
async def get_scan_status(
    scan_id: str = Path(..., description="Unique scan identifier"),
    db: Session = Depends(get_db),
    api_key: db_models.APIKey = Depends(get_current_api_key),
) -> ScanStatusResponse:
    """Get the status of a specific scan."""
    repo = ScanRepository(db)
    scan = repo.get_by_id(scan_id)

    if not scan:
        raise HTTPException(
            status_code=404,
            detail={"error": "not_found", "message": f"Scan {scan_id} not found"}
        )

    return ScanStatusResponse(
        id=scan.id,
        target=scan.target,
        status=ScanStatus(scan.status.value),
        progress=scan.progress,
        current_phase=scan.current_phase,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        vulnerabilities_found=len(scan.vulnerabilities) if scan.vulnerabilities else 0
    )


@router.get(
    "/{scan_id}/results",
    response_model=ScanResultsResponse,
    summary="Get scan results",
    description="Get the full results of a completed scan",
    responses={
        404: {"model": ErrorResponse, "description": "Scan not found"},
        409: {"model": ErrorResponse, "description": "Scan not yet completed"},
    }
)
async def get_scan_results(
    scan_id: str = Path(..., description="Unique scan identifier"),
    db: Session = Depends(get_db),
    api_key: db_models.APIKey = Depends(get_current_api_key),
) -> ScanResultsResponse:
    """Get the full results of a completed scan."""
    repo = ScanRepository(db)
    scan = repo.get_by_id(scan_id)

    if not scan:
        raise HTTPException(
            status_code=404,
            detail={"error": "not_found", "message": f"Scan {scan_id} not found"}
        )

    # Allow viewing results for completed, failed, or cancelled scans
    finished_statuses = [
        db_models.ScanStatus.COMPLETED,
        db_models.ScanStatus.FAILED,
        db_models.ScanStatus.CANCELLED
    ]
    if scan.status not in finished_statuses:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "scan_not_complete",
                "message": f"Scan is still {scan.status.value}. Results will be available when complete."
            }
        )

    # Calculate duration
    duration = scan.duration_seconds

    # Convert vulnerabilities to response format
    vulnerabilities = [
        VulnerabilityResponse(
            id=v.id,
            type=VulnerabilityType(v.type.value),
            severity=VulnerabilitySeverity(v.severity.value),
            title=v.title,
            description=v.description,
            endpoint=v.endpoint,
            evidence=v.evidence,
            details=v.details,
            discovered_at=v.discovered_at,
        )
        for v in (scan.vulnerabilities or [])
    ]

    # Convert technologies to response format
    technologies = [
        TechnologyResponse(
            name=t.name,
            version=t.version,
            confidence=t.confidence,
            evidence=t.evidence,
        )
        for t in (scan.technologies or [])
    ]

    # Get login endpoint URLs
    login_endpoints = [ep.url for ep in (scan.login_endpoints or [])]

    # Generate summary
    vuln_count = len(vulnerabilities)
    critical_count = sum(1 for v in vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL)
    high_count = sum(1 for v in vulnerabilities if v.severity == VulnerabilitySeverity.HIGH)

    summary = f"Scan of {scan.target} found {vuln_count} vulnerabilities"
    if critical_count:
        summary += f" ({critical_count} critical, {high_count} high)"
    summary += "."

    return ScanResultsResponse(
        id=scan.id,
        target=scan.target,
        status=ScanStatus(scan.status.value),
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        duration_seconds=duration,
        vulnerabilities=vulnerabilities,
        technologies=technologies,
        subdomains=scan.subdomains or [],
        login_endpoints=login_endpoints,
        errors=[],  # Errors are in error_message field
        summary=summary
    )


@router.delete(
    "/{scan_id}",
    status_code=204,
    summary="Cancel a scan",
    description="Cancel a running or pending scan",
    responses={
        404: {"model": ErrorResponse, "description": "Scan not found"},
        409: {"model": ErrorResponse, "description": "Scan cannot be cancelled"},
    }
)
async def cancel_scan(
    scan_id: str = Path(..., description="Unique scan identifier"),
    db: Session = Depends(get_db),
    api_key: db_models.APIKey = Depends(get_current_api_key),
) -> None:
    """Cancel a running or pending scan."""
    repo = ScanRepository(db)
    scan = repo.get_by_id(scan_id)

    if not scan:
        raise HTTPException(
            status_code=404,
            detail={"error": "not_found", "message": f"Scan {scan_id} not found"}
        )

    # Only allow cancelling pending or running scans
    cancellable_statuses = [db_models.ScanStatus.PENDING, db_models.ScanStatus.RUNNING]
    if scan.status not in cancellable_statuses:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "cannot_cancel",
                "message": f"Cannot cancel scan with status {scan.status.value}"
            }
        )

    # Update scan status
    repo.update_status(scan_id, db_models.ScanStatus.CANCELLED, "Scan cancelled by user")

    # Try to cancel the Celery task
    try:
        from vull_scanner.worker import cancel_scan as celery_cancel
        celery_cancel.delay(scan_id)
    except Exception:
        pass  # Best effort cancellation

    return None
