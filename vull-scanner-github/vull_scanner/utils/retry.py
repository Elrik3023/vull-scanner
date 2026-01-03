"""Retry utilities with exponential backoff."""

import time
import random
from functools import wraps
from typing import Callable, TypeVar, Type, Any

T = TypeVar("T")


class RetryExhausted(Exception):
    """Raised when all retry attempts have been exhausted."""

    def __init__(self, message: str, last_exception: Exception | None = None):
        super().__init__(message)
        self.last_exception = last_exception


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: tuple[Type[Exception], ...] = (Exception,),
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator for retry with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts.
        base_delay: Initial delay between retries in seconds.
        max_delay: Maximum delay between retries.
        exponential_base: Base for exponential backoff.
        jitter: Add random jitter to delay.
        retryable_exceptions: Tuple of exceptions to retry on.

    Returns:
        Decorated function.

    Example:
        @retry_with_backoff(max_retries=3, retryable_exceptions=(httpx.TimeoutException,))
        def fetch_data(url):
            return httpx.get(url)
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exception: Exception | None = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e

                    if attempt == max_retries:
                        # Last attempt, re-raise
                        raise

                    # Calculate delay with exponential backoff
                    delay = min(
                        base_delay * (exponential_base**attempt),
                        max_delay,
                    )

                    # Add jitter to prevent thundering herd
                    if jitter:
                        delay += random.uniform(0, delay * 0.1)

                    time.sleep(delay)

            # Should not reach here, but just in case
            raise RetryExhausted(
                f"Exhausted {max_retries} retries", last_exception=last_exception
            )

        return wrapper

    return decorator


def retry_on_rate_limit(
    max_retries: int = 5,
    rate_limit_codes: tuple[int, ...] = (429, 503),
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator for retrying on rate limit responses.

    Respects Retry-After header if present.

    Args:
        max_retries: Maximum number of retry attempts.
        rate_limit_codes: HTTP status codes indicating rate limiting.

    Returns:
        Decorated function.
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            import httpx

            for attempt in range(max_retries + 1):
                try:
                    result = func(*args, **kwargs)

                    # Check if result is an HTTP response
                    if isinstance(result, httpx.Response):
                        if result.status_code in rate_limit_codes:
                            if attempt == max_retries:
                                return result

                            # Get retry delay from Retry-After header
                            retry_after = result.headers.get("Retry-After")
                            if retry_after:
                                try:
                                    delay = float(retry_after)
                                except ValueError:
                                    delay = 5.0  # Default
                            else:
                                delay = 2.0 * (attempt + 1)

                            time.sleep(min(delay, 60.0))
                            continue

                    return result

                except Exception:
                    if attempt == max_retries:
                        raise
                    time.sleep(2.0 * (attempt + 1))

            # Should not reach here
            raise RetryExhausted(f"Exhausted {max_retries} retries")

        return wrapper

    return decorator


class RetryContext:
    """Context manager for retry logic with cleanup.

    Example:
        with RetryContext(max_retries=3) as retry:
            while retry.should_continue():
                try:
                    result = do_something()
                    break
                except Exception as e:
                    retry.record_failure(e)
    """

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.attempt = 0
        self.last_exception: Exception | None = None

    def __enter__(self) -> "RetryContext":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        return False

    def should_continue(self) -> bool:
        """Check if more attempts should be made.

        Returns:
            True if more attempts available.
        """
        return self.attempt <= self.max_retries

    def record_failure(self, exception: Exception) -> None:
        """Record a failed attempt and wait before next retry.

        Args:
            exception: The exception that occurred.
        """
        self.last_exception = exception
        self.attempt += 1

        if self.attempt <= self.max_retries:
            delay = min(
                self.base_delay * (2 ** (self.attempt - 1)),
                self.max_delay,
            )
            delay += random.uniform(0, delay * 0.1)
            time.sleep(delay)

    @property
    def exhausted(self) -> bool:
        """Check if all retries have been exhausted.

        Returns:
            True if no more retries available.
        """
        return self.attempt > self.max_retries
