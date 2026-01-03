"""Tests for the FastAPI REST API."""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture
def test_client():
    """Create a test client for the API."""
    from vull_scanner.api.main import app
    from vull_scanner.db.database import engine
    from vull_scanner.db.models import Base

    # Create tables
    Base.metadata.create_all(bind=engine)

    with TestClient(app) as client:
        yield client

    # Cleanup
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def mock_api_key():
    """Create a mock API key for testing."""
    from vull_scanner.db.database import get_db_context
    from vull_scanner.db.repositories import APIKeyRepository
    from vull_scanner.api.auth import generate_api_key

    plain_key, hashed_key = generate_api_key()

    with get_db_context() as db:
        repo = APIKeyRepository(db)
        api_key = repo.create(
            key_hash=hashed_key,
            name="Test API Key",
            is_admin=True,
        )

    return plain_key


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_check(self, test_client):
        """Test basic health check."""
        response = test_client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data

    def test_liveness_check(self, test_client):
        """Test liveness probe."""
        response = test_client.get("/health/live")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"

    def test_readiness_check(self, test_client):
        """Test readiness probe."""
        response = test_client.get("/health/ready")

        assert response.status_code == 200
        data = response.json()
        assert "checks" in data


class TestScanEndpoints:
    """Tests for scan management endpoints."""

    def test_create_scan_unauthorized(self, test_client):
        """Test that creating scan without auth returns 401."""
        response = test_client.post(
            "/api/v1/scans",
            json={"target": "example.com"}
        )

        assert response.status_code == 401

    def test_create_scan_with_api_key(self, test_client, mock_api_key):
        """Test creating a scan with valid API key."""
        with patch("vull_scanner.worker.execute_scan") as mock_task:
            mock_task.delay = MagicMock()

            response = test_client.post(
                "/api/v1/scans",
                json={"target": "example.com"},
                headers={"X-API-Key": mock_api_key}
            )

        assert response.status_code == 201
        data = response.json()
        assert "id" in data
        assert data["target"] == "example.com"
        assert data["status"] == "pending"

    def test_create_scan_invalid_target(self, test_client, mock_api_key):
        """Test creating scan with invalid target."""
        response = test_client.post(
            "/api/v1/scans",
            json={"target": "localhost"},
            headers={"X-API-Key": mock_api_key}
        )

        assert response.status_code == 400
        data = response.json()
        assert "error" in data["detail"]

    def test_list_scans_empty(self, test_client, mock_api_key):
        """Test listing scans when none exist."""
        response = test_client.get(
            "/api/v1/scans",
            headers={"X-API-Key": mock_api_key}
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_get_scan_not_found(self, test_client, mock_api_key):
        """Test getting non-existent scan."""
        response = test_client.get(
            "/api/v1/scans/nonexistent-id",
            headers={"X-API-Key": mock_api_key}
        )

        assert response.status_code == 404

    def test_scan_workflow(self, test_client, mock_api_key):
        """Test complete scan workflow."""
        with patch("vull_scanner.worker.execute_scan") as mock_task:
            mock_task.delay = MagicMock()

            # Create scan
            create_response = test_client.post(
                "/api/v1/scans",
                json={"target": "example.com"},
                headers={"X-API-Key": mock_api_key}
            )
            assert create_response.status_code == 201
            scan_id = create_response.json()["id"]

            # Get status
            status_response = test_client.get(
                f"/api/v1/scans/{scan_id}",
                headers={"X-API-Key": mock_api_key}
            )
            assert status_response.status_code == 200
            assert status_response.json()["id"] == scan_id

            # Cancel scan
            cancel_response = test_client.delete(
                f"/api/v1/scans/{scan_id}",
                headers={"X-API-Key": mock_api_key}
            )
            assert cancel_response.status_code == 204


class TestAuthEndpoints:
    """Tests for authentication endpoints."""

    def test_get_current_key_info(self, test_client, mock_api_key):
        """Test getting current API key info."""
        response = test_client.get(
            "/api/v1/auth/keys/me",
            headers={"X-API-Key": mock_api_key}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test API Key"
        assert data["is_admin"] is True

    def test_get_jwt_token(self, test_client, mock_api_key):
        """Test getting JWT token."""
        response = test_client.post(
            "/api/v1/auth/token",
            headers={"X-API-Key": mock_api_key}
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_use_jwt_token(self, test_client, mock_api_key):
        """Test using JWT token for authentication."""
        # Get JWT token
        token_response = test_client.post(
            "/api/v1/auth/token",
            headers={"X-API-Key": mock_api_key}
        )
        token = token_response.json()["access_token"]

        # Use JWT token
        response = test_client.get(
            "/api/v1/auth/keys/me",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200

    def test_create_api_key_requires_admin(self, test_client):
        """Test that creating API key requires admin access."""
        from vull_scanner.db.database import get_db_context
        from vull_scanner.db.repositories import APIKeyRepository
        from vull_scanner.api.auth import generate_api_key

        # Create non-admin key
        plain_key, hashed_key = generate_api_key()
        with get_db_context() as db:
            repo = APIKeyRepository(db)
            repo.create(
                key_hash=hashed_key,
                name="Non-Admin Key",
                is_admin=False,
            )

        response = test_client.post(
            "/api/v1/auth/keys",
            json={"name": "New Key"},
            headers={"X-API-Key": plain_key}
        )

        assert response.status_code == 403

    def test_list_api_keys(self, test_client, mock_api_key):
        """Test listing API keys."""
        response = test_client.get(
            "/api/v1/auth/keys",
            headers={"X-API-Key": mock_api_key}
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1


class TestRootEndpoint:
    """Tests for root endpoint."""

    def test_root_endpoint(self, test_client):
        """Test root endpoint returns API info."""
        response = test_client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "version" in data
        assert "docs" in data
