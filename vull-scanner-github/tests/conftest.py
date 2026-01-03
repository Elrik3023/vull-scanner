"""Pytest configuration and shared fixtures."""

import os
import pytest
from unittest.mock import MagicMock, patch

# Set test environment variables before importing scanner modules
os.environ.setdefault("OPENAI_API_KEY", "test-api-key-for-testing")


@pytest.fixture
def sample_html_with_login_form():
    """Sample HTML page with a login form."""
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Login Page</title></head>
    <body>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <input type="hidden" name="_csrf" value="token123">
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """


@pytest.fixture
def sample_html_without_forms():
    """Sample HTML page without any forms."""
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Welcome</title></head>
    <body>
        <h1>Welcome to our website</h1>
        <p>No login form here.</p>
    </body>
    </html>
    """


@pytest.fixture
def sample_nmap_xml_output():
    """Sample Nmap XML output for testing."""
    return """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" args="nmap -sV example.com">
        <host>
            <status state="up"/>
            <address addr="93.184.216.34" addrtype="ipv4"/>
            <hostnames>
                <hostname name="example.com" type="user"/>
            </hostnames>
            <ports>
                <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http" product="Apache" version="2.4.41"/>
                </port>
                <port protocol="tcp" portid="443">
                    <state state="open"/>
                    <service name="https" product="Apache" version="2.4.41"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """


@pytest.fixture
def sample_ffuf_json_output():
    """Sample FFUF JSON output for testing."""
    return {
        "results": [
            {
                "input": {"FUZZ": "admin"},
                "position": 1,
                "status": 200,
                "length": 1234,
                "words": 100,
                "lines": 50,
                "content-type": "text/html",
                "redirectlocation": "",
                "url": "http://example.com/admin"
            },
            {
                "input": {"FUZZ": "login"},
                "position": 2,
                "status": 200,
                "length": 567,
                "words": 50,
                "lines": 25,
                "content-type": "text/html",
                "redirectlocation": "",
                "url": "http://example.com/login"
            }
        ]
    }


@pytest.fixture
def mock_httpx_client():
    """Mock httpx client for testing HTTP requests."""
    with patch("httpx.Client") as mock_client:
        client_instance = MagicMock()
        mock_client.return_value = client_instance
        yield client_instance


@pytest.fixture
def scanner_state_minimal():
    """Minimal scanner state for testing."""
    from vull_scanner.state import ScannerState

    return {
        "target_url": "example.com",
        "allow_private": False,
        "show_passwords": False,
        "port_scan": None,
        "messages": [],
        "login_endpoints": [],
        "detected_technologies": [],
        "wordlist_selection": None,
        "nmap_result": None,
        "ffuf_result": None,
        "ffuf_results": [],
        "amass_result": None,
        "discovered_subdomains": [],
        "injectable_endpoints": [],
        "sqlmap_results": [],
        "burp_results": [],
        "credential_results": [],
        "errors": [],
        "current_phase": "init",
    }


@pytest.fixture
def mock_external_tools():
    """Mock all external tools (nmap, ffuf, amass, sqlmap)."""
    with patch("shutil.which") as mock_which:
        mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}" if cmd in ["nmap", "ffuf", "amass", "sqlmap"] else None
        yield mock_which
