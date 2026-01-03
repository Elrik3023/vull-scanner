"""Tests for retry utilities."""

import pytest
from unittest.mock import MagicMock, patch
from vull_scanner.utils.retry import (
    retry_with_backoff,
    RetryExhausted,
    RetryContext,
)


class TestRetryWithBackoff:
    """Tests for retry_with_backoff decorator."""

    def test_successful_on_first_attempt(self):
        """Test function succeeds on first attempt."""
        call_count = 0

        @retry_with_backoff(max_retries=3)
        def succeed():
            nonlocal call_count
            call_count += 1
            return "success"

        result = succeed()
        assert result == "success"
        assert call_count == 1

    def test_succeeds_after_retries(self):
        """Test function succeeds after a few retries."""
        call_count = 0

        @retry_with_backoff(max_retries=3, base_delay=0.01)
        def fail_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Not yet")
            return "success"

        result = fail_then_succeed()
        assert result == "success"
        assert call_count == 3

    def test_exhausts_retries(self):
        """Test that exception is raised after exhausting retries."""
        call_count = 0

        @retry_with_backoff(max_retries=2, base_delay=0.01)
        def always_fail():
            nonlocal call_count
            call_count += 1
            raise ValueError("Always fails")

        with pytest.raises(ValueError, match="Always fails"):
            always_fail()

        assert call_count == 3  # Initial + 2 retries

    def test_only_retries_specified_exceptions(self):
        """Test that only specified exceptions trigger retries."""
        call_count = 0

        @retry_with_backoff(
            max_retries=3,
            base_delay=0.01,
            retryable_exceptions=(ValueError,)
        )
        def raise_type_error():
            nonlocal call_count
            call_count += 1
            raise TypeError("Not retryable")

        with pytest.raises(TypeError):
            raise_type_error()

        assert call_count == 1  # No retries for TypeError

    def test_respects_max_delay(self):
        """Test that delay is capped at max_delay."""
        with patch("time.sleep") as mock_sleep:
            call_count = 0

            @retry_with_backoff(
                max_retries=5,
                base_delay=1.0,
                max_delay=5.0,
                exponential_base=10.0,  # Would exceed max quickly
                jitter=False
            )
            def always_fail():
                nonlocal call_count
                call_count += 1
                raise ValueError("Fail")

            with pytest.raises(ValueError):
                always_fail()

            # Check that no sleep call exceeded max_delay
            for call in mock_sleep.call_args_list:
                assert call[0][0] <= 5.0


class TestRetryContext:
    """Tests for RetryContext context manager."""

    def test_successful_first_attempt(self):
        """Test successful operation on first attempt."""
        attempts = 0

        with RetryContext(max_retries=3) as retry:
            while retry.should_continue():
                attempts += 1
                break  # Success on first try

        assert attempts == 1
        assert not retry.exhausted

    def test_success_after_failures(self):
        """Test success after some failures."""
        attempts = 0

        with RetryContext(max_retries=3, base_delay=0.01) as retry:
            while retry.should_continue():
                attempts += 1
                if attempts < 3:
                    retry.record_failure(ValueError("Not yet"))
                else:
                    break

        assert attempts == 3
        assert not retry.exhausted

    def test_exhausted_retries(self):
        """Test when all retries are exhausted."""
        attempts = 0

        with RetryContext(max_retries=2, base_delay=0.01) as retry:
            while retry.should_continue():
                attempts += 1
                retry.record_failure(ValueError("Always fails"))

        assert attempts == 3  # Initial + 2 retries
        assert retry.exhausted
        assert isinstance(retry.last_exception, ValueError)

    def test_last_exception_tracked(self):
        """Test that last exception is properly tracked."""
        with RetryContext(max_retries=2, base_delay=0.01) as retry:
            while retry.should_continue():
                try:
                    raise ValueError("Specific error")
                except ValueError as e:
                    retry.record_failure(e)

        assert retry.last_exception is not None
        assert str(retry.last_exception) == "Specific error"


class TestRetryExhausted:
    """Tests for RetryExhausted exception."""

    def test_exception_message(self):
        """Test exception message."""
        exc = RetryExhausted("Max retries exceeded")
        assert str(exc) == "Max retries exceeded"
        assert exc.last_exception is None

    def test_exception_with_last_exception(self):
        """Test exception with last exception attached."""
        original = ValueError("Original error")
        exc = RetryExhausted("Max retries exceeded", last_exception=original)
        assert exc.last_exception is original
        assert str(exc.last_exception) == "Original error"
