"""Rate limiting for the VULL Scanner API.

Implements:
- Per-API-key rate limiting (scans per day)
- Per-IP rate limiting for unauthenticated requests
- Global concurrent scan limiting
"""

import time
from dataclasses import dataclass, field
from collections import defaultdict
from threading import Lock
from typing import Optional
from datetime import datetime, timedelta

from fastapi import Request, HTTPException, status


@dataclass
class RateLimitState:
    """Tracks rate limit state for a key."""

    requests: list[float] = field(default_factory=list)
    daily_scans: int = 0
    daily_reset: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(days=1))


class RateLimiter:
    """In-memory rate limiter.

    For production with multiple workers, use Redis-based rate limiting.
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        scans_per_day: int = 100,
        max_concurrent_scans: int = 10,
    ):
        """Initialize rate limiter.

        Args:
            requests_per_minute: Max API requests per minute per key.
            scans_per_day: Max scans per day per API key.
            max_concurrent_scans: Max concurrent scans globally.
        """
        self.requests_per_minute = requests_per_minute
        self.scans_per_day = scans_per_day
        self.max_concurrent_scans = max_concurrent_scans

        self._state: dict[str, RateLimitState] = defaultdict(RateLimitState)
        self._concurrent_scans = 0
        self._lock = Lock()

    def _get_key(self, request: Request, api_key_id: Optional[str] = None) -> str:
        """Get rate limit key from request."""
        if api_key_id:
            return f"key:{api_key_id}"
        # Fall back to IP for unauthenticated requests
        client_ip = request.client.host if request.client else "unknown"
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        return f"ip:{client_ip}"

    def _cleanup_old_requests(self, state: RateLimitState) -> None:
        """Remove requests older than 1 minute."""
        cutoff = time.time() - 60
        state.requests = [r for r in state.requests if r > cutoff]

    def _reset_daily_if_needed(self, state: RateLimitState) -> None:
        """Reset daily counters if past reset time."""
        now = datetime.utcnow()
        if now >= state.daily_reset:
            state.daily_scans = 0
            state.daily_reset = now + timedelta(days=1)

    def check_rate_limit(
        self,
        request: Request,
        api_key_id: Optional[str] = None,
    ) -> None:
        """Check if request is within rate limits.

        Args:
            request: The incoming request.
            api_key_id: API key ID if authenticated.

        Raises:
            HTTPException: If rate limit exceeded.
        """
        key = self._get_key(request, api_key_id)

        with self._lock:
            state = self._state[key]
            self._cleanup_old_requests(state)

            if len(state.requests) >= self.requests_per_minute:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "rate_limit_exceeded",
                        "message": f"Rate limit exceeded. Max {self.requests_per_minute} requests per minute.",
                        "retry_after": 60,
                    },
                    headers={"Retry-After": "60"},
                )

            state.requests.append(time.time())

    def check_scan_limit(
        self,
        request: Request,
        api_key_id: str,
    ) -> None:
        """Check if scan is within daily limits.

        Args:
            request: The incoming request.
            api_key_id: API key ID.

        Raises:
            HTTPException: If scan limit exceeded.
        """
        key = self._get_key(request, api_key_id)

        with self._lock:
            state = self._state[key]
            self._reset_daily_if_needed(state)

            if state.daily_scans >= self.scans_per_day:
                seconds_until_reset = (state.daily_reset - datetime.utcnow()).total_seconds()
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "scan_limit_exceeded",
                        "message": f"Daily scan limit exceeded. Max {self.scans_per_day} scans per day.",
                        "retry_after": int(seconds_until_reset),
                    },
                    headers={"Retry-After": str(int(seconds_until_reset))},
                )

    def check_concurrent_limit(self) -> None:
        """Check if under concurrent scan limit.

        Raises:
            HTTPException: If concurrent limit exceeded.
        """
        with self._lock:
            if self._concurrent_scans >= self.max_concurrent_scans:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "concurrent_limit_exceeded",
                        "message": f"Too many concurrent scans. Max {self.max_concurrent_scans} concurrent scans.",
                        "retry_after": 30,
                    },
                    headers={"Retry-After": "30"},
                )

    def increment_scan_count(self, request: Request, api_key_id: str) -> None:
        """Increment daily scan count and concurrent scan count.

        Call this when a scan is successfully started.
        """
        key = self._get_key(request, api_key_id)

        with self._lock:
            state = self._state[key]
            self._reset_daily_if_needed(state)
            state.daily_scans += 1
            self._concurrent_scans += 1

    def decrement_concurrent_scans(self) -> None:
        """Decrement concurrent scan count.

        Call this when a scan completes or fails.
        """
        with self._lock:
            self._concurrent_scans = max(0, self._concurrent_scans - 1)

    def get_limits_info(
        self,
        request: Request,
        api_key_id: Optional[str] = None,
    ) -> dict:
        """Get current rate limit info for a key.

        Returns:
            Dict with limit info for headers.
        """
        key = self._get_key(request, api_key_id)

        with self._lock:
            state = self._state[key]
            self._cleanup_old_requests(state)
            self._reset_daily_if_needed(state)

            return {
                "X-RateLimit-Limit": str(self.requests_per_minute),
                "X-RateLimit-Remaining": str(max(0, self.requests_per_minute - len(state.requests))),
                "X-RateLimit-Reset": str(int(time.time()) + 60),
                "X-ScanLimit-Limit": str(self.scans_per_day),
                "X-ScanLimit-Remaining": str(max(0, self.scans_per_day - state.daily_scans)),
                "X-ScanLimit-Reset": str(int(state.daily_reset.timestamp())),
            }


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        from vull_scanner.config import get_config
        config = get_config()
        _rate_limiter = RateLimiter(
            requests_per_minute=config.rate_limit.max_requests_per_minute // 10,  # Per minute from per-minute config
            scans_per_day=100,  # Default daily scan limit
            max_concurrent_scans=config.rate_limit.max_concurrent_scans,
        )
    return _rate_limiter


def reset_rate_limiter() -> None:
    """Reset global rate limiter (for testing)."""
    global _rate_limiter
    _rate_limiter = None


class RateLimitMiddleware:
    """ASGI middleware for per-request rate limiting.

    Applies rate limiting to all API requests based on API key or IP.
    """

    # Paths exempt from rate limiting
    EXEMPT_PATHS = {"/", "/health", "/health/live", "/health/ready", "/metrics", "/docs", "/redoc", "/openapi.json"}

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Skip rate limiting for exempt paths
        if path in self.EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        # Create a minimal request-like object for rate limiting
        from starlette.requests import Request
        request = Request(scope, receive)

        # Get API key ID from header if present
        api_key_id = None
        api_key_header = request.headers.get("x-api-key")
        if api_key_header:
            # Hash it to get the key ID (simplified - in production would do DB lookup)
            import hashlib
            api_key_id = hashlib.sha256(api_key_header.encode()).hexdigest()[:16]

        rate_limiter = get_rate_limiter()

        try:
            rate_limiter.check_rate_limit(request, api_key_id)
        except HTTPException as e:
            # Return 429 response
            from starlette.responses import JSONResponse
            response = JSONResponse(
                status_code=e.status_code,
                content=e.detail,
                headers=e.headers,
            )
            await response(scope, receive, send)
            return

        # Add rate limit headers to response
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                limit_info = rate_limiter.get_limits_info(request, api_key_id)
                for key, value in limit_info.items():
                    headers[key.lower().encode()] = value.encode()
                message["headers"] = list(headers.items())
            await send(message)

        await self.app(scope, receive, send_with_headers)
