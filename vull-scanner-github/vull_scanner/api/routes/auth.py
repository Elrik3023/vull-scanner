"""Authentication and API key management endpoints."""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from vull_scanner.db.database import get_db
from vull_scanner.db.repositories import APIKeyRepository
from vull_scanner.db.models import APIKey
from vull_scanner.api.auth import (
    generate_api_key,
    create_jwt_token,
    get_current_api_key,
    require_admin,
    hash_api_key,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


class APIKeyCreateRequest(BaseModel):
    """Request to create a new API key."""
    name: str = Field(..., min_length=1, max_length=100, description="Name for the API key")
    is_admin: bool = Field(default=False, description="Whether this is an admin key")
    rate_limit_daily: int = Field(default=100, ge=1, le=10000, description="Daily scan limit")
    rate_limit_concurrent: int = Field(default=10, ge=1, le=100, description="Concurrent scan limit")
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365, description="Days until expiration")


class APIKeyResponse(BaseModel):
    """Response containing API key info."""
    id: str
    name: str
    key: Optional[str] = Field(None, description="Only returned on creation")
    is_admin: bool
    is_active: bool
    rate_limit_daily: int
    rate_limit_concurrent: int
    scans_today: int
    scans_total: int
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]


class TokenResponse(BaseModel):
    """Response containing JWT token."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Seconds until expiration")


@router.post(
    "/keys",
    response_model=APIKeyResponse,
    status_code=201,
    summary="Create a new API key",
    description="Create a new API key. Requires admin access.",
)
async def create_api_key(
    request: APIKeyCreateRequest,
    admin_key: APIKey = Depends(require_admin),
    db: Session = Depends(get_db),
) -> APIKeyResponse:
    """Create a new API key.

    The plain text key is only returned once in this response.
    Store it securely - it cannot be retrieved later.
    """
    # Generate new key
    plain_key, hashed_key = generate_api_key()

    # Calculate expiration
    expires_at = None
    if request.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=request.expires_in_days)

    # Create in database
    repo = APIKeyRepository(db)
    db_key = repo.create(
        key_hash=hashed_key,
        name=request.name,
        is_admin=request.is_admin,
        rate_limit_daily=request.rate_limit_daily,
        rate_limit_concurrent=request.rate_limit_concurrent,
    )

    # Set expiration if provided
    if expires_at:
        db_key.expires_at = expires_at
        db.commit()
        db.refresh(db_key)

    return APIKeyResponse(
        id=db_key.id,
        name=db_key.name,
        key=plain_key,  # Only time the plain key is returned
        is_admin=db_key.is_admin,
        is_active=db_key.is_active,
        rate_limit_daily=db_key.rate_limit_daily,
        rate_limit_concurrent=db_key.rate_limit_concurrent,
        scans_today=db_key.scans_today,
        scans_total=db_key.scans_total,
        created_at=db_key.created_at,
        expires_at=db_key.expires_at,
        last_used_at=db_key.last_used_at,
    )


@router.get(
    "/keys",
    response_model=list[APIKeyResponse],
    summary="List all API keys",
    description="List all API keys. Requires admin access.",
)
async def list_api_keys(
    include_inactive: bool = Query(False, description="Include deactivated keys"),
    admin_key: APIKey = Depends(require_admin),
    db: Session = Depends(get_db),
) -> list[APIKeyResponse]:
    """List all API keys."""
    repo = APIKeyRepository(db)
    keys = repo.list_all(include_inactive=include_inactive)

    return [
        APIKeyResponse(
            id=k.id,
            name=k.name,
            key=None,  # Never return the key after creation
            is_admin=k.is_admin,
            is_active=k.is_active,
            rate_limit_daily=k.rate_limit_daily,
            rate_limit_concurrent=k.rate_limit_concurrent,
            scans_today=k.scans_today,
            scans_total=k.scans_total,
            created_at=k.created_at,
            expires_at=k.expires_at,
            last_used_at=k.last_used_at,
        )
        for k in keys
    ]


@router.get(
    "/keys/me",
    response_model=APIKeyResponse,
    summary="Get current API key info",
    description="Get information about the currently authenticated API key.",
)
async def get_current_key_info(
    api_key: APIKey = Depends(get_current_api_key),
) -> APIKeyResponse:
    """Get info about the current API key."""
    return APIKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key=None,
        is_admin=api_key.is_admin,
        is_active=api_key.is_active,
        rate_limit_daily=api_key.rate_limit_daily,
        rate_limit_concurrent=api_key.rate_limit_concurrent,
        scans_today=api_key.scans_today,
        scans_total=api_key.scans_total,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
    )


@router.delete(
    "/keys/{key_id}",
    status_code=204,
    summary="Deactivate an API key",
    description="Deactivate an API key. Requires admin access.",
)
async def deactivate_api_key(
    key_id: str,
    admin_key: APIKey = Depends(require_admin),
    db: Session = Depends(get_db),
) -> None:
    """Deactivate an API key."""
    # Prevent deactivating own key
    if key_id == admin_key.id:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "message": "Cannot deactivate your own API key"}
        )

    repo = APIKeyRepository(db)
    if not repo.deactivate(key_id):
        raise HTTPException(
            status_code=404,
            detail={"error": "not_found", "message": f"API key {key_id} not found"}
        )


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Get JWT token",
    description="Exchange API key for a short-lived JWT token.",
)
async def get_jwt_token(
    api_key: APIKey = Depends(get_current_api_key),
) -> TokenResponse:
    """Get a JWT token for the current API key.

    JWT tokens can be used as Bearer tokens and expire after 24 hours.
    """
    from vull_scanner.api.auth import JWT_EXPIRATION_HOURS

    token = create_jwt_token(api_key.id)
    expires_in = JWT_EXPIRATION_HOURS * 3600  # Convert to seconds

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
    )
