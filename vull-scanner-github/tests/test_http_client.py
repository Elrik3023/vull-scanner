"""Tests for HTTP client pool."""

import os
import pytest
from unittest.mock import patch, MagicMock
import threading

from vull_scanner.utils.http_client import (
    HTTPClientPool,
    get_http_client,
    get_ssl_verify,
    cleanup_http_clients,
)


class TestGetSslVerify:
    """Tests for SSL verification setting."""

    def test_default_verify_enabled(self):
        """Test that SSL verification is enabled by default."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("VULL_SKIP_SSL_VERIFY", None)
            assert get_ssl_verify() is True

    def test_skip_ssl_with_true(self):
        """Test that VULL_SKIP_SSL_VERIFY=true disables verification."""
        with patch.dict(os.environ, {"VULL_SKIP_SSL_VERIFY": "true"}):
            assert get_ssl_verify() is False

    def test_skip_ssl_with_1(self):
        """Test that VULL_SKIP_SSL_VERIFY=1 disables verification."""
        with patch.dict(os.environ, {"VULL_SKIP_SSL_VERIFY": "1"}):
            assert get_ssl_verify() is False

    def test_skip_ssl_with_yes(self):
        """Test that VULL_SKIP_SSL_VERIFY=yes disables verification."""
        with patch.dict(os.environ, {"VULL_SKIP_SSL_VERIFY": "yes"}):
            assert get_ssl_verify() is False

    def test_skip_ssl_case_insensitive(self):
        """Test that the check is case-insensitive."""
        with patch.dict(os.environ, {"VULL_SKIP_SSL_VERIFY": "TRUE"}):
            assert get_ssl_verify() is False

    def test_other_values_enable_verify(self):
        """Test that other values keep verification enabled."""
        with patch.dict(os.environ, {"VULL_SKIP_SSL_VERIFY": "false"}):
            assert get_ssl_verify() is True


class TestHTTPClientPool:
    """Tests for HTTPClientPool class."""

    def setup_method(self):
        """Reset singleton before each test."""
        HTTPClientPool.reset()

    def teardown_method(self):
        """Clean up after each test."""
        HTTPClientPool.reset()

    def test_singleton_pattern(self):
        """Test that get_instance returns the same instance."""
        pool1 = HTTPClientPool.get_instance()
        pool2 = HTTPClientPool.get_instance()
        assert pool1 is pool2

    def test_reset_creates_new_instance(self):
        """Test that reset allows new instance creation."""
        pool1 = HTTPClientPool.get_instance()
        HTTPClientPool.reset()
        pool2 = HTTPClientPool.get_instance()
        assert pool1 is not pool2

    @patch("httpx.Client")
    def test_get_client_creates_client(self, mock_client_class):
        """Test that get_client creates an HTTP client."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        pool = HTTPClientPool()
        client = pool.get_client()

        mock_client_class.assert_called_once()
        assert client is mock_client

    @patch("httpx.Client")
    def test_get_client_reuses_client_same_thread(self, mock_client_class):
        """Test that same client is reused for same thread."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        pool = HTTPClientPool()
        client1 = pool.get_client()
        client2 = pool.get_client()

        # Should only create one client
        assert mock_client_class.call_count == 1
        assert client1 is client2

    @patch("httpx.Client")
    def test_get_client_different_threads(self, mock_client_class):
        """Test that different threads get different clients."""
        clients = []

        def get_client_in_thread(pool):
            clients.append(pool.get_client())

        pool = HTTPClientPool()

        # Create clients in different threads
        thread1 = threading.Thread(target=get_client_in_thread, args=(pool,))
        thread2 = threading.Thread(target=get_client_in_thread, args=(pool,))

        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()

        # Should have created two clients
        assert mock_client_class.call_count == 2

    @patch("httpx.Client")
    def test_close_all_clients(self, mock_client_class):
        """Test that close_all closes all clients."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        pool = HTTPClientPool()
        pool.get_client()
        pool.close_all()

        mock_client.close.assert_called_once()

    @patch("httpx.Client")
    def test_close_thread_client(self, mock_client_class):
        """Test that close_thread_client closes only current thread's client."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        pool = HTTPClientPool()
        pool.get_client()
        pool.close_thread_client()

        mock_client.close.assert_called_once()


class TestGetHttpClient:
    """Tests for get_http_client function."""

    def setup_method(self):
        """Reset singleton before each test."""
        HTTPClientPool.reset()

    def teardown_method(self):
        """Clean up after each test."""
        HTTPClientPool.reset()

    @patch("httpx.Client")
    def test_get_http_client_uses_pool(self, mock_client_class):
        """Test that get_http_client uses the singleton pool."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        client = get_http_client()

        assert client is mock_client

    @patch("httpx.Client")
    def test_get_http_client_with_timeout_override(self, mock_client_class):
        """Test that timeout override is respected."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        get_http_client(timeout=30.0)

        # Check that the client was created with the specified timeout
        call_kwargs = mock_client_class.call_args[1]
        assert call_kwargs["timeout"] == 30.0


class TestCleanupHttpClients:
    """Tests for cleanup_http_clients function."""

    def setup_method(self):
        """Reset singleton before each test."""
        HTTPClientPool.reset()

    def teardown_method(self):
        """Clean up after each test."""
        HTTPClientPool.reset()

    @patch("httpx.Client")
    def test_cleanup_closes_all(self, mock_client_class):
        """Test that cleanup_http_clients closes all clients."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        get_http_client()
        cleanup_http_clients()

        mock_client.close.assert_called_once()
