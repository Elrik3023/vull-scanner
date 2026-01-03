"""Tests for input validation and SSRF prevention."""

import pytest
from vull_scanner.utils.validation import (
    validate_target,
    validate_port,
    sanitize_path,
    is_valid_url,
    ValidationError,
)


class TestValidateTarget:
    """Tests for validate_target function."""

    def test_valid_domain(self):
        """Test validation of a valid domain."""
        result = validate_target("example.com")
        assert result == "example.com"

    def test_valid_domain_with_http(self):
        """Test validation of a domain with http scheme."""
        result = validate_target("http://example.com")
        assert result == "example.com"

    def test_valid_domain_with_https(self):
        """Test validation of a domain with https scheme."""
        result = validate_target("https://example.com")
        assert result == "example.com"

    def test_valid_domain_with_path(self):
        """Test validation strips path and returns hostname."""
        result = validate_target("https://example.com/login")
        assert result == "example.com"

    def test_valid_domain_with_port(self):
        """Test validation strips port and returns hostname."""
        result = validate_target("https://example.com:8080")
        assert result == "example.com"

    def test_empty_target_raises(self):
        """Test that empty target raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_target("")

    def test_whitespace_only_raises(self):
        """Test that whitespace-only target raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_target("   ")

    def test_localhost_blocked(self):
        """Test that localhost is blocked."""
        with pytest.raises(ValidationError, match="not allowed"):
            validate_target("localhost")

    def test_127_0_0_1_blocked(self):
        """Test that 127.0.0.1 is blocked."""
        with pytest.raises(ValidationError, match="not allowed"):
            validate_target("127.0.0.1")

    def test_ipv6_localhost_blocked(self):
        """Test that IPv6 localhost is blocked."""
        with pytest.raises(ValidationError, match="not allowed"):
            validate_target("::1")

    def test_cloud_metadata_blocked(self):
        """Test that AWS metadata endpoint is blocked."""
        with pytest.raises(ValidationError, match="not allowed"):
            validate_target("169.254.169.254")

    def test_google_metadata_blocked(self):
        """Test that Google Cloud metadata endpoint is blocked."""
        with pytest.raises(ValidationError, match="not allowed"):
            validate_target("metadata.google.internal")

    def test_private_ip_10_blocked_by_default(self):
        """Test that 10.x.x.x is blocked by default."""
        with pytest.raises(ValidationError, match="Private IP not allowed"):
            validate_target("10.0.0.1")

    def test_private_ip_172_blocked_by_default(self):
        """Test that 172.16.x.x is blocked by default."""
        with pytest.raises(ValidationError, match="Private IP not allowed"):
            validate_target("172.16.0.1")

    def test_private_ip_192_blocked_by_default(self):
        """Test that 192.168.x.x is blocked by default."""
        with pytest.raises(ValidationError, match="Private IP not allowed"):
            validate_target("192.168.1.1")

    def test_private_ip_allowed_with_flag(self):
        """Test that private IPs are allowed with allow_private=True."""
        result = validate_target("192.168.1.1", allow_private=True)
        assert result == "192.168.1.1"

    def test_public_ip_allowed(self):
        """Test that public IPs are allowed."""
        result = validate_target("93.184.216.34")
        assert result == "93.184.216.34"

    def test_invalid_scheme_rejected(self):
        """Test that non-http/https schemes are rejected."""
        with pytest.raises(ValidationError, match="Invalid scheme"):
            validate_target("ftp://example.com")

    def test_invalid_hostname_format(self):
        """Test that invalid hostname formats are rejected."""
        with pytest.raises(ValidationError, match="Invalid hostname"):
            validate_target("http://example..com")

    def test_subdomain_valid(self):
        """Test that subdomains are valid."""
        result = validate_target("admin.example.com")
        assert result == "admin.example.com"


class TestValidatePort:
    """Tests for validate_port function."""

    def test_valid_port_int(self):
        """Test validation of valid port as integer."""
        assert validate_port(80) == 80
        assert validate_port(443) == 443
        assert validate_port(8080) == 8080

    def test_valid_port_string(self):
        """Test validation of valid port as string."""
        assert validate_port("80") == 80
        assert validate_port("443") == 443

    def test_port_too_low(self):
        """Test that port 0 is rejected."""
        with pytest.raises(ValidationError, match="out of range"):
            validate_port(0)

    def test_port_too_high(self):
        """Test that port > 65535 is rejected."""
        with pytest.raises(ValidationError, match="out of range"):
            validate_port(65536)

    def test_invalid_port_string(self):
        """Test that non-numeric string is rejected."""
        with pytest.raises(ValidationError, match="Invalid port"):
            validate_port("abc")

    def test_boundary_ports(self):
        """Test boundary port values."""
        assert validate_port(1) == 1
        assert validate_port(65535) == 65535


class TestSanitizePath:
    """Tests for sanitize_path function."""

    def test_valid_path(self):
        """Test that valid paths pass through."""
        assert sanitize_path("login") == "login"
        assert sanitize_path("admin/login") == "admin/login"

    def test_empty_path(self):
        """Test that empty path is allowed."""
        assert sanitize_path("") == ""

    def test_path_traversal_blocked(self):
        """Test that path traversal is blocked."""
        with pytest.raises(ValidationError, match="Path traversal"):
            sanitize_path("../etc/passwd")

    def test_absolute_path_blocked(self):
        """Test that absolute paths are blocked."""
        with pytest.raises(ValidationError, match="Path traversal"):
            sanitize_path("/etc/passwd")

    def test_null_byte_blocked(self):
        """Test that null bytes are blocked."""
        with pytest.raises(ValidationError, match="Null byte"):
            sanitize_path("file\x00.txt")


class TestIsValidUrl:
    """Tests for is_valid_url function."""

    def test_valid_http_url(self):
        """Test that http URLs are valid."""
        assert is_valid_url("http://example.com") is True

    def test_valid_https_url(self):
        """Test that https URLs are valid."""
        assert is_valid_url("https://example.com") is True

    def test_url_with_path(self):
        """Test that URLs with paths are valid."""
        assert is_valid_url("https://example.com/login") is True

    def test_invalid_url_no_scheme(self):
        """Test that URLs without scheme are invalid."""
        assert is_valid_url("example.com") is False

    def test_invalid_url_empty(self):
        """Test that empty string is invalid."""
        assert is_valid_url("") is False
