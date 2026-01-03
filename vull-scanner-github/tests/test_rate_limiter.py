"""Tests for the rate limiter module."""

import pytest
import time
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
from fastapi import HTTPException

from vull_scanner.api.rate_limiter import (
    RateLimiter,
    RateLimitState,
    get_rate_limiter,
    reset_rate_limiter,
)


@pytest.fixture
def rate_limiter():
    """Create a rate limiter for testing."""
    return RateLimiter(
        requests_per_minute=10,
        scans_per_day=5,
        max_concurrent_scans=3,
    )


@pytest.fixture
def mock_request():
    """Create a mock request."""
    request = MagicMock()
    request.client.host = "192.168.1.1"
    request.headers.get.return_value = None
    return request


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_check_rate_limit_allows_request(self, rate_limiter, mock_request):
        """Test that rate limiter allows requests under limit."""
        # Should not raise for first request
        rate_limiter.check_rate_limit(mock_request)

    def test_check_rate_limit_blocks_excess_requests(self, rate_limiter, mock_request):
        """Test that rate limiter blocks requests over limit."""
        # Make 10 requests (at the limit)
        for _ in range(10):
            rate_limiter.check_rate_limit(mock_request)

        # 11th request should fail
        with pytest.raises(HTTPException) as exc_info:
            rate_limiter.check_rate_limit(mock_request)

        assert exc_info.value.status_code == 429
        assert "rate_limit_exceeded" in str(exc_info.value.detail)

    def test_check_rate_limit_resets_after_minute(self, rate_limiter, mock_request):
        """Test that rate limits reset after one minute."""
        # Make requests up to limit
        for _ in range(10):
            rate_limiter.check_rate_limit(mock_request)

        # Simulate time passing
        key = rate_limiter._get_key(mock_request)
        state = rate_limiter._state[key]
        # Set all requests to be over 60 seconds old
        state.requests = [time.time() - 61 for _ in range(10)]

        # Should now allow requests again
        rate_limiter.check_rate_limit(mock_request)

    def test_check_scan_limit_allows_scan(self, rate_limiter, mock_request):
        """Test that scan limiter allows scans under limit."""
        rate_limiter.check_scan_limit(mock_request, "test-key-id")

    def test_check_scan_limit_blocks_excess_scans(self, rate_limiter, mock_request):
        """Test that scan limiter blocks scans over daily limit."""
        # Increment up to the limit
        for _ in range(5):
            rate_limiter.increment_scan_count(mock_request, "test-key-id")

        # Next scan should fail
        with pytest.raises(HTTPException) as exc_info:
            rate_limiter.check_scan_limit(mock_request, "test-key-id")

        assert exc_info.value.status_code == 429
        assert "scan_limit_exceeded" in str(exc_info.value.detail)

    def test_scan_limit_resets_daily(self, rate_limiter, mock_request):
        """Test that scan limits reset after daily reset."""
        # Use up all scans
        for _ in range(5):
            rate_limiter.increment_scan_count(mock_request, "test-key-id")

        # Set reset time to the past
        key = rate_limiter._get_key(mock_request, "test-key-id")
        state = rate_limiter._state[key]
        state.daily_reset = datetime.utcnow() - timedelta(hours=1)

        # Should now allow scans again
        rate_limiter.check_scan_limit(mock_request, "test-key-id")

    def test_check_concurrent_limit_allows_scans(self, rate_limiter):
        """Test that concurrent limiter allows scans under limit."""
        rate_limiter.check_concurrent_limit()

    def test_check_concurrent_limit_blocks_excess_scans(self, rate_limiter, mock_request):
        """Test that concurrent limiter blocks excess scans."""
        # Increment to max concurrent
        for _ in range(3):
            rate_limiter.increment_scan_count(mock_request, "test-key")

        # Next concurrent check should fail
        with pytest.raises(HTTPException) as exc_info:
            rate_limiter.check_concurrent_limit()

        assert exc_info.value.status_code == 429
        assert "concurrent_limit_exceeded" in str(exc_info.value.detail)

    def test_decrement_concurrent_scans(self, rate_limiter, mock_request):
        """Test decrementing concurrent scan count."""
        # Increment
        rate_limiter.increment_scan_count(mock_request, "test-key")
        assert rate_limiter._concurrent_scans == 1

        # Decrement
        rate_limiter.decrement_concurrent_scans()
        assert rate_limiter._concurrent_scans == 0

    def test_decrement_concurrent_scans_floor_at_zero(self, rate_limiter):
        """Test that concurrent scans don't go below zero."""
        rate_limiter.decrement_concurrent_scans()
        assert rate_limiter._concurrent_scans == 0

        rate_limiter.decrement_concurrent_scans()
        assert rate_limiter._concurrent_scans == 0

    def test_get_key_with_api_key(self, rate_limiter, mock_request):
        """Test key generation with API key ID."""
        key = rate_limiter._get_key(mock_request, "my-key-id")
        assert key == "key:my-key-id"

    def test_get_key_with_ip(self, rate_limiter, mock_request):
        """Test key generation with IP address."""
        key = rate_limiter._get_key(mock_request)
        assert key == "ip:192.168.1.1"

    def test_get_key_with_forwarded_header(self, rate_limiter, mock_request):
        """Test key generation with X-Forwarded-For header."""
        mock_request.headers.get.return_value = "10.0.0.1, 192.168.1.1"
        key = rate_limiter._get_key(mock_request)
        assert key == "ip:10.0.0.1"

    def test_get_limits_info(self, rate_limiter, mock_request):
        """Test getting rate limit info for headers."""
        info = rate_limiter.get_limits_info(mock_request, "test-key")

        assert "X-RateLimit-Limit" in info
        assert "X-RateLimit-Remaining" in info
        assert "X-ScanLimit-Limit" in info
        assert "X-ScanLimit-Remaining" in info

        assert info["X-RateLimit-Limit"] == "10"
        assert info["X-ScanLimit-Limit"] == "5"

    def test_limits_info_updates_with_requests(self, rate_limiter, mock_request):
        """Test that limits info updates after requests."""
        # Initial state
        info = rate_limiter.get_limits_info(mock_request, "test-key")
        assert info["X-RateLimit-Remaining"] == "10"

        # Make some requests
        for _ in range(3):
            rate_limiter.check_rate_limit(mock_request, "test-key")

        # Check updated state
        info = rate_limiter.get_limits_info(mock_request, "test-key")
        assert info["X-RateLimit-Remaining"] == "7"


class TestGlobalRateLimiter:
    """Tests for global rate limiter functions."""

    def test_get_rate_limiter_returns_singleton(self):
        """Test that get_rate_limiter returns same instance."""
        reset_rate_limiter()

        limiter1 = get_rate_limiter()
        limiter2 = get_rate_limiter()

        assert limiter1 is limiter2

    def test_reset_rate_limiter_clears_instance(self):
        """Test that reset_rate_limiter clears the global instance."""
        limiter1 = get_rate_limiter()
        reset_rate_limiter()
        limiter2 = get_rate_limiter()

        assert limiter1 is not limiter2


class TestRateLimitState:
    """Tests for RateLimitState dataclass."""

    def test_default_values(self):
        """Test default values for rate limit state."""
        state = RateLimitState()

        assert state.requests == []
        assert state.daily_scans == 0
        assert state.daily_reset > datetime.utcnow()

    def test_request_tracking(self):
        """Test that requests can be tracked."""
        state = RateLimitState()
        state.requests.append(time.time())
        state.requests.append(time.time())

        assert len(state.requests) == 2

    def test_daily_scan_tracking(self):
        """Test daily scan counting."""
        state = RateLimitState()
        state.daily_scans = 5

        assert state.daily_scans == 5
