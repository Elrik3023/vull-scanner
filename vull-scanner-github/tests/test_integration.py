"""Integration tests with mocked external tools."""

import pytest
from unittest.mock import patch, MagicMock
import subprocess


class TestInputNodeIntegration:
    """Integration tests for input node with validation."""

    def test_valid_target_passes_through(self):
        """Test that valid targets are processed correctly."""
        from vull_scanner.nodes.input_node import input_node

        state = {
            "target_url": "https://example.com",
            "allow_private": False,
        }

        result = input_node(state)

        assert result["target_url"] == "example.com"
        assert result["current_phase"] == "port_scan"

    def test_private_ip_blocked_by_default(self):
        """Test that private IPs are blocked without allow_private flag."""
        from vull_scanner.nodes.input_node import input_node
        from vull_scanner.utils.validation import ValidationError

        state = {
            "target_url": "192.168.1.1",
            "allow_private": False,
        }

        with pytest.raises(ValidationError, match="Private IP"):
            input_node(state)

    def test_private_ip_allowed_with_flag(self):
        """Test that private IPs are allowed with allow_private flag."""
        from vull_scanner.nodes.input_node import input_node

        state = {
            "target_url": "192.168.1.1",
            "allow_private": True,
        }

        result = input_node(state)

        assert result["target_url"] == "192.168.1.1"


class TestNmapScannerIntegration:
    """Integration tests for nmap scanner with mocked subprocess."""

    @pytest.fixture
    def mock_nmap_output(self, sample_nmap_xml_output):
        """Mock nmap subprocess output."""
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = sample_nmap_xml_output.encode()
            mock_result.stderr = b""
            mock_run.return_value = mock_result
            yield mock_run

    @pytest.fixture
    def mock_nmap_available(self):
        """Mock nmap as available."""
        with patch("shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/nmap"
            yield mock_which

    def test_nmap_result_parsing(self, sample_nmap_xml_output):
        """Test parsing of nmap XML output."""
        import xml.etree.ElementTree as ET

        root = ET.fromstring(sample_nmap_xml_output)
        hosts = root.findall(".//host")

        assert len(hosts) == 1

        ports = hosts[0].findall(".//port")
        assert len(ports) == 2

        port_80 = ports[0]
        assert port_80.get("portid") == "80"
        assert port_80.find("state").get("state") == "open"


class TestFFUFScannerIntegration:
    """Integration tests for FFUF scanner with mocked subprocess."""

    @pytest.fixture
    def mock_ffuf_output(self, sample_ffuf_json_output):
        """Mock ffuf subprocess output."""
        import json

        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = json.dumps(sample_ffuf_json_output).encode()
            mock_result.stderr = b""
            mock_run.return_value = mock_result
            yield mock_run

    def test_ffuf_json_parsing(self, sample_ffuf_json_output):
        """Test parsing of FFUF JSON output."""
        results = sample_ffuf_json_output["results"]

        assert len(results) == 2
        assert results[0]["url"] == "http://example.com/admin"
        assert results[1]["url"] == "http://example.com/login"


class TestCredentialTesterIntegration:
    """Integration tests for credential tester with mocked HTTP."""

    @pytest.fixture
    def mock_http_responses(self):
        """Mock HTTP responses for credential testing."""
        import httpx

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()

            # Simulate failed login (default)
            failed_response = MagicMock(spec=httpx.Response)
            failed_response.status_code = 200
            failed_response.text = "Invalid username or password"
            failed_response.headers = {}
            failed_response.url = MagicMock()
            failed_response.url.path = "/login"

            # Simulate successful login
            success_response = MagicMock(spec=httpx.Response)
            success_response.status_code = 302
            success_response.text = ""
            success_response.headers = {"location": "/dashboard"}
            success_response.url = MagicMock()
            success_response.url.path = "/login"

            # Return failed by default, success for specific creds
            def post_side_effect(url, **kwargs):
                data = kwargs.get("data", {})
                if data.get("username") == "admin" and data.get("password") == "admin123":
                    return success_response
                return failed_response

            mock_client.post.side_effect = post_side_effect
            mock_client_class.return_value = mock_client
            mock_client_class.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_class.return_value.__exit__ = MagicMock(return_value=False)

            yield mock_client

    def test_success_detection_redirect(self):
        """Test success detection via redirect to dashboard."""
        from vull_scanner.nodes.credential_tester import _detect_success
        import httpx

        response = MagicMock(spec=httpx.Response)
        response.status_code = 302
        response.headers = {"location": "/dashboard"}
        response.text = ""

        success, evidence = _detect_success(response, "admin")

        assert success is True
        assert "dashboard" in evidence.lower()

    def test_failure_detection_error_message(self):
        """Test failure detection via error message."""
        from vull_scanner.nodes.credential_tester import _detect_success
        import httpx

        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.headers = {}
        response.text = "Invalid username or password. Please try again."
        response.url = MagicMock()
        response.url.path = "/login"

        success, evidence = _detect_success(response, "admin")

        assert success is False
        assert "invalid" in evidence.lower()

    def test_success_detection_session_cookie(self):
        """Test success detection via session cookie."""
        from vull_scanner.nodes.credential_tester import _detect_success
        import httpx

        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.headers = {"set-cookie": "session_id=abc123; Path=/; HttpOnly"}
        response.text = "Welcome to the dashboard"
        response.url = MagicMock()
        response.url.path = "/dashboard"

        success, evidence = _detect_success(response, "admin")

        assert success is True


class TestPortScannerIntegration:
    """Integration tests for port scanner."""

    @pytest.fixture
    def mock_socket(self):
        """Mock socket connections."""
        with patch("socket.socket") as mock_socket_class:
            mock_sock = MagicMock()
            mock_socket_class.return_value = mock_sock
            mock_sock.__enter__ = MagicMock(return_value=mock_sock)
            mock_sock.__exit__ = MagicMock(return_value=False)
            yield mock_sock

    def test_port_scan_both_open(self, mock_socket):
        """Test port scanning when both ports are open."""
        mock_socket.connect_ex.return_value = 0  # Success

        from vull_scanner.nodes.port_scanner import port_scanner_node

        state = {"target_url": "example.com"}
        result = port_scanner_node(state)

        assert result["port_scan"].port_80_open is True
        assert result["port_scan"].port_443_open is True

    def test_port_scan_only_https(self, mock_socket):
        """Test port scanning when only HTTPS is open."""
        def connect_side_effect(addr):
            if addr[1] == 80:
                return 1  # Connection refused
            return 0  # Success

        mock_socket.connect_ex.side_effect = connect_side_effect

        from vull_scanner.nodes.port_scanner import port_scanner_node

        state = {"target_url": "example.com"}
        result = port_scanner_node(state)

        assert result["port_scan"].port_80_open is False
        assert result["port_scan"].port_443_open is True
        assert result["port_scan"].preferred_protocol == "https"


class TestHTMLToolsIntegration:
    """Integration tests for HTML parsing tools."""

    def test_extract_login_form(self, sample_html_with_login_form):
        """Test extracting login form from HTML."""
        from vull_scanner.tools.html_tools import extract_forms

        forms = extract_forms(sample_html_with_login_form)

        assert len(forms) >= 1
        # Check that we found a form with password field
        has_password_field = any(
            "password" in str(form).lower()
            for form in forms
        )
        assert has_password_field

    def test_no_forms_in_page(self, sample_html_without_forms):
        """Test handling page without forms."""
        from vull_scanner.tools.html_tools import extract_forms

        forms = extract_forms(sample_html_without_forms)

        assert len(forms) == 0


class TestExternalToolsIntegration:
    """Integration tests for external tool detection."""

    def test_tool_detection_available(self):
        """Test detection of available tools."""
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}" if cmd in ["nmap", "ffuf"] else None

            from vull_scanner.utils.external_tools import get_available_tools

            tools = get_available_tools()

            assert tools["nmap"] is True
            assert tools["ffuf"] is True

    def test_tool_detection_not_available(self):
        """Test detection when tools are not installed."""
        with patch("shutil.which") as mock_which:
            mock_which.return_value = None

            from vull_scanner.utils.external_tools import get_available_tools

            tools = get_available_tools()

            assert tools["nmap"] is False
            assert tools["ffuf"] is False
