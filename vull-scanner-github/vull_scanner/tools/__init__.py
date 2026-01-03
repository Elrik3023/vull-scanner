"""LLM tools for login discovery and security scanning."""

from vull_scanner.tools.http_tools import fetch_page, fetch_robots_txt
from vull_scanner.tools.html_tools import extract_links, extract_forms, analyze_form
from vull_scanner.tools.scanner_tools import (
    check_available_scanners,
    nmap_scan,
    ffuf_directory_scan,
    ffuf_login_discovery,
    ffuf_api_discovery,
    amass_subdomain_enum,
)

# All tools available to the LLM
TOOLS = [
    # HTTP/HTML tools
    fetch_page,
    fetch_robots_txt,
    extract_links,
    extract_forms,
    analyze_form,
    # External scanner tools
    check_available_scanners,
    nmap_scan,
    ffuf_directory_scan,
    ffuf_login_discovery,
    ffuf_api_discovery,
    amass_subdomain_enum,
]

__all__ = [
    # HTTP/HTML tools
    "fetch_page",
    "fetch_robots_txt",
    "extract_links",
    "extract_forms",
    "analyze_form",
    # Scanner tools
    "check_available_scanners",
    "nmap_scan",
    "ffuf_directory_scan",
    "ffuf_login_discovery",
    "ffuf_api_discovery",
    "amass_subdomain_enum",
    # Tool list
    "TOOLS",
]
