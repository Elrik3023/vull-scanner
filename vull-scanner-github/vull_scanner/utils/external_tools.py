"""External security tools wrapper utilities (nmap, ffuf, amass)."""

import subprocess
import shutil
import json
import tempfile
import os
from pathlib import Path
from dataclasses import dataclass


@dataclass
class ToolResult:
    """Result from running an external tool."""
    success: bool
    output: str
    error: str = ""
    parsed_data: dict | list | None = None


def check_tool_installed(tool_name: str) -> bool:
    """Check if an external tool is installed and available in PATH."""
    return shutil.which(tool_name) is not None


def get_available_tools() -> dict[str, bool]:
    """Get availability status of all external tools."""
    tools = ["nmap", "ffuf", "amass"]
    return {tool: check_tool_installed(tool) for tool in tools}


# =============================================================================
# NMAP - Network Scanner
# =============================================================================

def run_nmap(
    target: str,
    ports: str = "80,443,8080,8443",
    scan_type: str = "service",
    timeout: int = 120,
) -> ToolResult:
    """Run nmap scan on a target.

    Args:
        target: Target hostname or IP address.
        ports: Comma-separated list of ports or range (e.g., "80,443" or "1-1000").
        scan_type: Type of scan - "quick", "service", "aggressive", or "vuln".
        timeout: Maximum time in seconds for the scan.

    Returns:
        ToolResult with scan output and parsed data.
    """
    if not check_tool_installed("nmap"):
        return ToolResult(
            success=False,
            output="",
            error="nmap is not installed. Install with: sudo apt install nmap",
        )

    # Build nmap command based on scan type
    cmd = ["nmap", "-oX", "-"]  # Output XML to stdout

    if scan_type == "quick":
        cmd.extend(["-T4", "-F", target])  # Fast scan, top 100 ports
    elif scan_type == "service":
        cmd.extend(["-sV", "-p", ports, target])  # Service version detection
    elif scan_type == "aggressive":
        cmd.extend(["-A", "-p", ports, target])  # Aggressive scan with OS detection
    elif scan_type == "vuln":
        cmd.extend(["--script", "vuln", "-p", ports, target])  # Vulnerability scripts
    else:
        cmd.extend(["-p", ports, target])  # Basic port scan

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        # Parse the XML output
        parsed = _parse_nmap_output(result.stdout)

        return ToolResult(
            success=result.returncode == 0,
            output=result.stdout,
            error=result.stderr,
            parsed_data=parsed,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(
            success=False,
            output="",
            error=f"nmap scan timed out after {timeout} seconds",
        )
    except Exception as e:
        return ToolResult(
            success=False,
            output="",
            error=f"Error running nmap: {str(e)}",
        )


def _parse_nmap_output(xml_output: str) -> dict:
    """Parse nmap XML output into a structured dict."""
    import re

    parsed = {
        "hosts": [],
        "open_ports": [],
        "services": [],
    }

    # Extract open ports and services using regex (simple parsing)
    # Format: <port protocol="tcp" portid="80"><state state="open"/><service name="http"/>
    port_pattern = r'<port protocol="(\w+)" portid="(\d+)".*?<state state="(\w+)".*?(?:<service name="([^"]*)".*?product="([^"]*)".*?version="([^"]*)")?'

    for match in re.finditer(port_pattern, xml_output, re.DOTALL):
        protocol, port, state, service, product, version = match.groups()
        if state == "open":
            port_info = {
                "port": int(port),
                "protocol": protocol,
                "state": state,
                "service": service or "unknown",
                "product": product or "",
                "version": version or "",
            }
            parsed["open_ports"].append(int(port))
            parsed["services"].append(port_info)

    # Extract host info
    host_pattern = r'<address addr="([^"]+)" addrtype="(\w+)"'
    for match in re.finditer(host_pattern, xml_output):
        addr, addr_type = match.groups()
        parsed["hosts"].append({"address": addr, "type": addr_type})

    return parsed


# =============================================================================
# FFUF - Web Fuzzer
# =============================================================================

def run_ffuf(
    target_url: str,
    wordlist: str,
    mode: str = "dir",
    extensions: str = "",
    filters: dict | None = None,
    timeout: int = 300,
    rate: int = 100,
) -> ToolResult:
    """Run ffuf web fuzzer.

    Args:
        target_url: Target URL with FUZZ keyword (e.g., "https://example.com/FUZZ").
        wordlist: Path to wordlist file.
        mode: Fuzzing mode - "dir" (directory), "vhost" (virtual host), or "param".
        extensions: Comma-separated extensions to append (e.g., "php,html,txt").
        filters: Dict of filters like {"fc": "404", "fs": "1234"} (filter codes/sizes).
        timeout: Maximum time in seconds.
        rate: Requests per second.

    Returns:
        ToolResult with discovered paths.
    """
    if not check_tool_installed("ffuf"):
        return ToolResult(
            success=False,
            output="",
            error="ffuf is not installed. Install from: https://github.com/ffuf/ffuf",
        )

    # Validate wordlist exists
    if not Path(wordlist).exists():
        return ToolResult(
            success=False,
            output="",
            error=f"Wordlist not found: {wordlist}",
        )

    # Create temp file for JSON output
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        output_file = f.name

    try:
        # Build ffuf command
        cmd = [
            "ffuf",
            "-u", target_url,
            "-w", wordlist,
            "-o", output_file,
            "-of", "json",
            "-rate", str(rate),
            "-t", "50",  # Threads
            "-timeout", "10",  # Request timeout
            "-s",  # Silent mode
        ]

        # Add extensions for directory mode
        if extensions and mode == "dir":
            cmd.extend(["-e", extensions])

        # Add filters
        if filters:
            if "fc" in filters:  # Filter status codes
                cmd.extend(["-fc", filters["fc"]])
            if "fs" in filters:  # Filter response size
                cmd.extend(["-fs", filters["fs"]])
            if "fw" in filters:  # Filter word count
                cmd.extend(["-fw", filters["fw"]])
        else:
            # Default: filter 404s
            cmd.extend(["-fc", "404"])

        # Add mode-specific options
        if mode == "vhost":
            cmd.extend(["-H", f"Host: FUZZ.{target_url.split('/')[2]}"])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        # Parse JSON output
        parsed = _parse_ffuf_output(output_file)

        # Read raw output for display
        output_text = f"Found {len(parsed)} results\n"
        for item in parsed[:20]:  # Limit display
            output_text += f"  [{item.get('status')}] {item.get('url')} (size: {item.get('length')})\n"
        if len(parsed) > 20:
            output_text += f"  ... and {len(parsed) - 20} more\n"

        return ToolResult(
            success=True,
            output=output_text,
            error=result.stderr,
            parsed_data=parsed,
        )

    except subprocess.TimeoutExpired:
        return ToolResult(
            success=False,
            output="",
            error=f"ffuf scan timed out after {timeout} seconds",
        )
    except Exception as e:
        return ToolResult(
            success=False,
            output="",
            error=f"Error running ffuf: {str(e)}",
        )
    finally:
        # Cleanup temp file
        if os.path.exists(output_file):
            os.unlink(output_file)


def _parse_ffuf_output(json_file: str) -> list[dict]:
    """Parse ffuf JSON output."""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)

        results = []
        for item in data.get("results", []):
            results.append({
                "url": item.get("url", ""),
                "status": item.get("status", 0),
                "length": item.get("length", 0),
                "words": item.get("words", 0),
                "lines": item.get("lines", 0),
                "input": item.get("input", {}).get("FUZZ", ""),
            })
        return results
    except (json.JSONDecodeError, FileNotFoundError):
        return []


# =============================================================================
# AMASS - Subdomain Enumeration
# =============================================================================

def run_amass(
    domain: str,
    mode: str = "passive",
    timeout: int = 300,
) -> ToolResult:
    """Run amass subdomain enumeration.

    Args:
        domain: Target domain (e.g., "example.com").
        mode: Enumeration mode - "passive" (safe, no direct contact) or "active".
        timeout: Maximum time in seconds.

    Returns:
        ToolResult with discovered subdomains.
    """
    if not check_tool_installed("amass"):
        return ToolResult(
            success=False,
            output="",
            error="amass is not installed. Install from: https://github.com/owasp-amass/amass",
        )

    # Create temp file for output
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        output_file = f.name

    try:
        # Build amass command
        if mode == "passive":
            cmd = [
                "amass", "enum",
                "-passive",
                "-d", domain,
                "-o", output_file,
                "-timeout", str(timeout // 60),  # amass uses minutes
            ]
        else:  # active
            cmd = [
                "amass", "enum",
                "-active",
                "-d", domain,
                "-o", output_file,
                "-timeout", str(timeout // 60),
            ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30,  # Extra buffer
        )

        # Read discovered subdomains
        subdomains = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]

        output_text = f"Found {len(subdomains)} subdomains:\n"
        for sub in subdomains[:30]:
            output_text += f"  - {sub}\n"
        if len(subdomains) > 30:
            output_text += f"  ... and {len(subdomains) - 30} more\n"

        return ToolResult(
            success=True,
            output=output_text,
            error=result.stderr,
            parsed_data={"subdomains": subdomains, "count": len(subdomains)},
        )

    except subprocess.TimeoutExpired:
        return ToolResult(
            success=False,
            output="",
            error=f"amass scan timed out after {timeout} seconds",
        )
    except Exception as e:
        return ToolResult(
            success=False,
            output="",
            error=f"Error running amass: {str(e)}",
        )
    finally:
        # Cleanup temp file
        if os.path.exists(output_file):
            os.unlink(output_file)


# =============================================================================
# Common Wordlists
# =============================================================================

def get_ffuf_wordlist(wordlist_type: str = "directories") -> str | None:
    """Get path to a common wordlist for ffuf.

    Args:
        wordlist_type: Type of wordlist - "directories", "files", "subdomains", "passwords".

    Returns:
        Path to wordlist or None if not found.
    """
    seclists_paths = [
        "/usr/share/seclists",
        os.path.expanduser("~/SecLists"),
        "/opt/seclists",
    ]

    wordlist_map = {
        "directories": [
            "Discovery/Web-Content/directory-list-2.3-medium.txt",
            "Discovery/Web-Content/directory-list-2.3-small.txt",
            "Discovery/Web-Content/common.txt",
        ],
        "files": [
            "Discovery/Web-Content/raft-medium-files.txt",
            "Discovery/Web-Content/raft-small-files.txt",
        ],
        "subdomains": [
            "Discovery/DNS/subdomains-top1million-5000.txt",
            "Discovery/DNS/subdomains-top1million-20000.txt",
        ],
        "api": [
            "Discovery/Web-Content/api/api-endpoints.txt",
            "Discovery/Web-Content/api/objects.txt",
        ],
        "admin": [
            "Discovery/Web-Content/quickhits.txt",
            "Discovery/Web-Content/Logins.fuzz.txt",
        ],
    }

    patterns = wordlist_map.get(wordlist_type, wordlist_map["directories"])

    for seclists_path in seclists_paths:
        for pattern in patterns:
            full_path = Path(seclists_path) / pattern
            if full_path.exists():
                return str(full_path)

    return None
