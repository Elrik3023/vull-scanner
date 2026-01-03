"""HTTP client pool with proper resource cleanup."""

import logging
import os
import threading
from typing import Any

import httpx

logger = logging.getLogger("vull_scanner.http_client")


def get_ssl_verify() -> bool:
    """Get SSL verification setting from environment.

    Returns:
        True to verify SSL certificates, False to skip verification.
    """
    skip_ssl = os.environ.get("VULL_SKIP_SSL_VERIFY", "").lower()
    return skip_ssl not in ("true", "1", "yes")


class HTTPClientPool:
    """Thread-safe pool of HTTP clients with automatic cleanup.

    Uses thread-local storage to provide one client per thread,
    with proper cleanup on shutdown.
    """

    _instance: "HTTPClientPool | None" = None
    _instance_lock = threading.Lock()

    def __init__(
        self,
        timeout: float = 10.0,
        max_connections: int = 100,
        follow_redirects: bool = True,
    ):
        """Initialize client pool.

        Args:
            timeout: Default request timeout in seconds.
            max_connections: Maximum connections per client.
            follow_redirects: Whether to follow redirects.
        """
        self._clients: dict[int, httpx.Client] = {}
        self._client_lock = threading.Lock()
        self._timeout = timeout
        self._max_connections = max_connections
        self._follow_redirects = follow_redirects
        self._verify = get_ssl_verify()

    @classmethod
    def get_instance(cls) -> "HTTPClientPool":
        """Get singleton instance of the client pool.

        Returns:
            HTTPClientPool instance.
        """
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def get_client(
        self,
        timeout: float | None = None,
        verify: bool | None = None,
    ) -> httpx.Client:
        """Get HTTP client for current thread.

        Args:
            timeout: Request timeout override.
            verify: SSL verification override.

        Returns:
            HTTP client instance.
        """
        thread_id = threading.get_ident()

        with self._client_lock:
            if thread_id not in self._clients:
                self._clients[thread_id] = httpx.Client(
                    timeout=timeout or self._timeout,
                    follow_redirects=self._follow_redirects,
                    verify=verify if verify is not None else self._verify,
                    limits=httpx.Limits(max_connections=self._max_connections),
                )
            return self._clients[thread_id]

    def close_thread_client(self) -> None:
        """Close the HTTP client for the current thread."""
        thread_id = threading.get_ident()

        with self._client_lock:
            if thread_id in self._clients:
                try:
                    self._clients[thread_id].close()
                except Exception as e:
                    logger.debug(f"Error closing HTTP client for thread {thread_id}: {e}")
                del self._clients[thread_id]

    def close_all(self) -> None:
        """Close all HTTP clients.

        Call this on scanner shutdown to clean up resources.
        """
        with self._client_lock:
            for thread_id, client in list(self._clients.items()):
                try:
                    client.close()
                except Exception as e:
                    logger.debug(f"Error closing HTTP client for thread {thread_id}: {e}")
            self._clients.clear()

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance.

        Closes all clients and allows a new instance to be created.
        """
        with cls._instance_lock:
            if cls._instance is not None:
                cls._instance.close_all()
                cls._instance = None


def get_http_client(
    timeout: float | None = None,
    verify: bool | None = None,
) -> httpx.Client:
    """Get HTTP client from the global pool.

    Args:
        timeout: Request timeout override.
        verify: SSL verification override.

    Returns:
        HTTP client instance.
    """
    return HTTPClientPool.get_instance().get_client(timeout=timeout, verify=verify)


def cleanup_http_clients() -> None:
    """Clean up all HTTP clients.

    Call this on scanner shutdown.
    """
    HTTPClientPool.get_instance().close_all()


def make_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    timeout: float | None = None,
    follow_redirects: bool = True,
) -> httpx.Response:
    """Make an HTTP request using the client pool.

    Args:
        url: Request URL.
        method: HTTP method.
        headers: Request headers.
        data: Form data for POST requests.
        timeout: Request timeout.
        follow_redirects: Whether to follow redirects.

    Returns:
        HTTP response.

    Raises:
        httpx.RequestError: On request failure.
    """
    client = get_http_client(timeout=timeout)

    if method.upper() == "GET":
        return client.get(url, headers=headers, follow_redirects=follow_redirects)
    elif method.upper() == "POST":
        return client.post(
            url, headers=headers, data=data, follow_redirects=follow_redirects
        )
    elif method.upper() == "HEAD":
        return client.head(url, headers=headers, follow_redirects=follow_redirects)
    else:
        return client.request(
            method, url, headers=headers, data=data, follow_redirects=follow_redirects
        )
