"""API authentication module."""

import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from jose import JWTError, jwt

from vull_scanner.db.database import get_db
from vull_scanner.db.repositories import APIKeyRepository
from vull_scanner.db.models import APIKey

# Security schemes
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)

# JWT Configuration
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "change-me-in-production-use-secrets")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.environ.get("JWT_EXPIRATION_HOURS", "24"))


def hash_api_key(key: str) -> str:
    """Hash an API key for storage.

    Args:
        key: Plain text API key.

    Returns:
        SHA256 hash of the key.
    """
    return hashlib.sha256(key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """Generate a new API key.

    Returns:
        Tuple of (plain_key, hashed_key).
        The plain key should be shown to the user once.
        The hashed key is stored in the database.
    """
    # Generate a secure random key
    plain_key = f"vull_{secrets.token_urlsafe(32)}"
    hashed_key = hash_api_key(plain_key)
    return plain_key, hashed_key


def create_jwt_token(
    api_key_id: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT token for an API key.

    Args:
        api_key_id: The API key ID to encode.
        expires_delta: Token expiration time.

    Returns:
        Encoded JWT token.
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)

    payload = {
        "sub": api_key_id,
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access",
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token.

    Args:
        token: The JWT token to decode.

    Returns:
        Decoded payload or None if invalid.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


async def get_api_key_from_header(
    api_key: Optional[str] = Security(api_key_header),
    db: Session = Depends(get_db),
) -> Optional[APIKey]:
    """Validate API key from X-API-Key header.

    Args:
        api_key: API key from header.
        db: Database session.

    Returns:
        APIKey model if valid, None otherwise.
    """
    if not api_key:
        return None

    # Hash the provided key and look it up
    key_hash = hash_api_key(api_key)
    repo = APIKeyRepository(db)
    db_key = repo.get_by_hash(key_hash)

    if not db_key:
        return None

    # Check if expired
    if db_key.expires_at and db_key.expires_at < datetime.utcnow():
        return None

    # Record usage
    repo.record_usage(db_key.id)

    return db_key


async def get_api_key_from_jwt(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    db: Session = Depends(get_db),
) -> Optional[APIKey]:
    """Validate JWT token from Authorization header.

    Args:
        credentials: Bearer token credentials.
        db: Database session.

    Returns:
        APIKey model if valid, None otherwise.
    """
    if not credentials:
        return None

    payload = decode_jwt_token(credentials.credentials)
    if not payload:
        return None

    api_key_id = payload.get("sub")
    if not api_key_id:
        return None

    repo = APIKeyRepository(db)
    db_key = repo.get_by_id(api_key_id)

    if not db_key or not db_key.is_active:
        return None

    # Check if expired
    if db_key.expires_at and db_key.expires_at < datetime.utcnow():
        return None

    return db_key


async def get_current_api_key(
    api_key_header: Optional[APIKey] = Depends(get_api_key_from_header),
    api_key_jwt: Optional[APIKey] = Depends(get_api_key_from_jwt),
) -> APIKey:
    """Get the current authenticated API key.

    Supports both X-API-Key header and Bearer JWT token.

    Args:
        api_key_header: API key from header.
        api_key_jwt: API key from JWT.

    Returns:
        Authenticated APIKey.

    Raises:
        HTTPException: If not authenticated.
    """
    # Try header first, then JWT
    api_key = api_key_header or api_key_jwt

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "unauthorized",
                "message": "Missing or invalid API key. Provide X-API-Key header or Bearer token.",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    return api_key


async def get_optional_api_key(
    api_key_header: Optional[APIKey] = Depends(get_api_key_from_header),
    api_key_jwt: Optional[APIKey] = Depends(get_api_key_from_jwt),
) -> Optional[APIKey]:
    """Get API key if provided, but don't require it.

    Useful for endpoints that work differently with/without auth.

    Returns:
        APIKey if authenticated, None otherwise.
    """
    return api_key_header or api_key_jwt


async def require_admin(
    api_key: APIKey = Depends(get_current_api_key),
) -> APIKey:
    """Require admin-level API key.

    Args:
        api_key: Current authenticated API key.

    Returns:
        Admin APIKey.

    Raises:
        HTTPException: If not admin.
    """
    if not api_key.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "forbidden",
                "message": "Admin access required.",
            },
        )
    return api_key


def check_rate_limit(api_key: APIKey) -> None:
    """Check if API key has exceeded rate limits.

    Args:
        api_key: API key to check.

    Raises:
        HTTPException: If rate limit exceeded.
    """
    if api_key.scans_today >= api_key.rate_limit_daily:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "rate_limit_exceeded",
                "message": f"Daily scan limit ({api_key.rate_limit_daily}) exceeded. Resets at midnight UTC.",
            },
            headers={"Retry-After": "3600"},
        )


def check_scan_limits(api_key: APIKey, request) -> None:
    """Check all scan-related rate limits.

    Checks both daily scan limit and global concurrent scan limit.

    Args:
        api_key: API key to check.
        request: FastAPI Request object.

    Raises:
        HTTPException: If any limit exceeded.
    """
    from vull_scanner.api.rate_limiter import get_rate_limiter

    rate_limiter = get_rate_limiter()

    # Check daily scan limit for this API key
    check_rate_limit(api_key)

    # Check global concurrent scan limit
    rate_limiter.check_concurrent_limit()

    # Check per-key scan limit from rate limiter
    rate_limiter.check_scan_limit(request, api_key.id)
