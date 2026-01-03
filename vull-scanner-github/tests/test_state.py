"""Tests for state schema models."""

import pytest
from vull_scanner.state import (
    PortScanResult,
    LoginEndpoint,
    CredentialTestResult,
    DetectedTechnology,
    WordlistSelection,
    NmapResult,
    PortInfo,
    SqlInjection,
    SqlmapResult,
)


class TestPortScanResult:
    """Tests for PortScanResult model."""

    def test_default_values(self):
        """Test default values are set correctly."""
        result = PortScanResult()
        assert result.port_80_open is False
        assert result.port_443_open is False
        assert result.preferred_protocol is None
        assert result.base_url is None

    def test_http_open(self):
        """Test when only HTTP port is open."""
        result = PortScanResult(
            port_80_open=True,
            port_443_open=False,
            preferred_protocol="http",
            base_url="http://example.com"
        )
        assert result.port_80_open is True
        assert result.preferred_protocol == "http"

    def test_https_open(self):
        """Test when only HTTPS port is open."""
        result = PortScanResult(
            port_80_open=False,
            port_443_open=True,
            preferred_protocol="https",
            base_url="https://example.com"
        )
        assert result.port_443_open is True
        assert result.preferred_protocol == "https"


class TestLoginEndpoint:
    """Tests for LoginEndpoint model."""

    def test_minimal_endpoint(self):
        """Test creating endpoint with minimal fields."""
        endpoint = LoginEndpoint(url="/login")
        assert endpoint.url == "/login"
        assert endpoint.method == "POST"
        assert endpoint.form_fields == []

    def test_full_endpoint(self):
        """Test creating endpoint with all fields."""
        endpoint = LoginEndpoint(
            url="https://example.com/login",
            method="POST",
            form_fields=["username", "password"],
            username_field="username",
            password_field="password",
            form_action="/auth/login",
            csrf_field="_token",
            additional_fields={"remember": "1"}
        )
        assert endpoint.url == "https://example.com/login"
        assert endpoint.method == "POST"
        assert "username" in endpoint.form_fields
        assert endpoint.csrf_field == "_token"
        assert endpoint.additional_fields["remember"] == "1"


class TestCredentialTestResult:
    """Tests for CredentialTestResult model."""

    def test_successful_login(self):
        """Test successful credential result."""
        result = CredentialTestResult(
            endpoint_url="https://example.com/login",
            username="admin",
            password="password123",
            success=True,
            response_code=302,
            evidence="Redirect to dashboard"
        )
        assert result.success is True
        assert result.username == "admin"
        assert result.response_code == 302

    def test_failed_login(self):
        """Test failed credential result."""
        result = CredentialTestResult(
            endpoint_url="https://example.com/login",
            username="admin",
            password="wrong",
            success=False,
            response_code=200,
            evidence="Invalid credentials message"
        )
        assert result.success is False


class TestDetectedTechnology:
    """Tests for DetectedTechnology model."""

    def test_wordpress_detection(self):
        """Test WordPress detection."""
        tech = DetectedTechnology(
            name="WordPress",
            confidence="high",
            evidence="wp-content directory found",
            version="6.4.2"
        )
        assert tech.name == "WordPress"
        assert tech.confidence == "high"
        assert tech.version == "6.4.2"

    def test_technology_without_version(self):
        """Test technology detection without version."""
        tech = DetectedTechnology(
            name="Apache",
            confidence="medium",
            evidence="Server header"
        )
        assert tech.name == "Apache"
        assert tech.version is None


class TestWordlistSelection:
    """Tests for WordlistSelection model."""

    def test_wordlist_selection(self):
        """Test wordlist selection with files."""
        selection = WordlistSelection(
            username_files=["/path/to/usernames.txt", "/path/to/admin-users.txt"],
            password_files=["/path/to/passwords.txt"],
            reasoning="WordPress detected, using CMS-specific lists"
        )
        assert len(selection.username_files) == 2
        assert len(selection.password_files) == 1
        assert "WordPress" in selection.reasoning


class TestNmapResult:
    """Tests for NmapResult model."""

    def test_empty_result(self):
        """Test empty Nmap result."""
        result = NmapResult()
        assert result.target == ""
        assert result.open_ports == []
        assert result.os_detection is None

    def test_result_with_ports(self):
        """Test Nmap result with open ports."""
        port80 = PortInfo(
            port=80,
            protocol="tcp",
            state="open",
            service="http",
            product="Apache",
            version="2.4.41"
        )
        port443 = PortInfo(
            port=443,
            protocol="tcp",
            state="open",
            service="https"
        )
        result = NmapResult(
            target="example.com",
            open_ports=[port80, port443],
            scan_time=5.2
        )
        assert result.target == "example.com"
        assert len(result.open_ports) == 2
        assert result.open_ports[0].port == 80


class TestSqlmapResult:
    """Tests for SqlmapResult model."""

    def test_not_vulnerable(self):
        """Test result when target is not vulnerable."""
        result = SqlmapResult(
            target_url="https://example.com/search?q=test",
            vulnerable=False
        )
        assert result.vulnerable is False
        assert result.injections == []

    def test_vulnerable_result(self):
        """Test result when SQL injection is found."""
        injection = SqlInjection(
            parameter="id",
            injection_type="boolean-based",
            payload="' OR '1'='1",
            dbms="MySQL"
        )
        result = SqlmapResult(
            target_url="https://example.com/item?id=1",
            vulnerable=True,
            injections=[injection],
            database_type="MySQL",
            databases_found=["information_schema", "app_db"]
        )
        assert result.vulnerable is True
        assert len(result.injections) == 1
        assert result.database_type == "MySQL"
