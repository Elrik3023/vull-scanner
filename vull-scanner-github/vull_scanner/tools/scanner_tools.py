"""LLM-callable tools for external security scanners (nmap, ffuf, amass)."""

import json
from langchain_core.tools import tool
from vull_scanner.utils.external_tools import (
    run_nmap,
    run_ffuf,
    run_amass,
    get_ffuf_wordlist,
    get_available_tools,
)


@tool
def check_available_scanners() -> str:
    """Check which external security scanners are available on this system.

    Call this first to see what tools you can use.

    Returns:
        JSON showing availability of nmap, ffuf, and amass.
    """
    tools = get_available_tools()
    result = {
        "available_tools": {name: available for name, available in tools.items()},
        "summary": [],
    }

    for name, available in tools.items():
        if available:
            result["summary"].append(f"{name}: AVAILABLE")
        else:
            result["summary"].append(f"{name}: NOT INSTALLED")

    return json.dumps(result, indent=2)


@tool
def nmap_scan(target: str, scan_type: str = "service", ports: str = "80,443,8080,8443,8000,3000") -> str:
    """Run nmap network scan on a target to discover open ports and services.

    Use this for detailed port scanning and service detection.
    Much more thorough than basic port checks.

    Args:
        target: Target hostname or IP address (e.g., "example.com" or "192.168.1.1")
        scan_type: Type of scan to perform:
            - "quick": Fast scan of top 100 ports
            - "service": Service version detection (recommended)
            - "aggressive": Full scan with OS detection (slower)
            - "vuln": Run vulnerability detection scripts (slowest)
        ports: Comma-separated ports or range (e.g., "80,443" or "1-1000")

    Returns:
        Scan results showing open ports, services, and versions.
    """
    result = run_nmap(target, ports=ports, scan_type=scan_type, timeout=180)

    if not result.success:
        return f"Error: {result.error}"

    if not result.parsed_data:
        return "No results found or unable to parse output."

    # Format output for LLM
    output = f"Nmap scan results for {target}:\n\n"

    services = result.parsed_data.get("services", [])
    if services:
        output += f"Found {len(services)} open port(s):\n"
        for svc in services:
            svc_info = f"  Port {svc['port']}/{svc['protocol']}: {svc['service']}"
            if svc.get('product'):
                svc_info += f" ({svc['product']}"
                if svc.get('version'):
                    svc_info += f" {svc['version']}"
                svc_info += ")"
            output += svc_info + "\n"
    else:
        output += "No open ports found in the scanned range.\n"

    return output


@tool
def ffuf_directory_scan(base_url: str, extensions: str = "php,html,txt,asp,aspx,jsp") -> str:
    """Run ffuf to discover hidden directories and files on a web server.

    Use this to find admin panels, backup files, hidden endpoints, and more.
    This is essential for finding login pages that aren't linked.

    Args:
        base_url: Base URL to scan (e.g., "https://example.com")
            The tool will automatically append /FUZZ for fuzzing.
        extensions: Comma-separated file extensions to try (e.g., "php,html,txt")
            Leave empty for directory-only scanning.

    Returns:
        List of discovered paths with their HTTP status codes.
    """
    # Get a wordlist
    wordlist = get_ffuf_wordlist("directories")
    if not wordlist:
        wordlist = get_ffuf_wordlist("admin")
    if not wordlist:
        return "Error: No wordlist found. Please ensure SecLists is installed."

    # Build the target URL with FUZZ keyword
    target_url = f"{base_url.rstrip('/')}/FUZZ"

    result = run_ffuf(
        target_url=target_url,
        wordlist=wordlist,
        mode="dir",
        extensions=extensions,
        filters={"fc": "404,403"},
        timeout=300,
        rate=100,
    )

    if not result.success:
        return f"Error: {result.error}"

    if not result.parsed_data:
        return "No hidden directories or files found."

    # Format output for LLM
    output = f"FFUF directory scan results for {base_url}:\n\n"
    output += f"Found {len(result.parsed_data)} path(s):\n"

    # Group by status code
    by_status = {}
    for item in result.parsed_data:
        status = item.get("status", 0)
        if status not in by_status:
            by_status[status] = []
        by_status[status].append(item)

    for status in sorted(by_status.keys()):
        items = by_status[status]
        output += f"\n  Status {status} ({len(items)} results):\n"
        for item in items[:15]:  # Limit per status
            output += f"    - {item.get('url')} (size: {item.get('length')})\n"
        if len(items) > 15:
            output += f"    ... and {len(items) - 15} more\n"

    return output


@tool
def ffuf_login_discovery(base_url: str) -> str:
    """Run ffuf specifically to find login and authentication pages.

    Uses a specialized wordlist focused on login endpoints.
    This is targeted for finding login pages specifically.

    Args:
        base_url: Base URL to scan (e.g., "https://example.com")

    Returns:
        List of potential login pages found.
    """
    # Get admin/login wordlist
    wordlist = get_ffuf_wordlist("admin")
    if not wordlist:
        wordlist = get_ffuf_wordlist("directories")
    if not wordlist:
        return "Error: No wordlist found. Please ensure SecLists is installed."

    target_url = f"{base_url.rstrip('/')}/FUZZ"

    result = run_ffuf(
        target_url=target_url,
        wordlist=wordlist,
        mode="dir",
        extensions="php,html,asp,aspx,jsp",
        filters={"fc": "404,403,500"},
        timeout=180,
        rate=150,
    )

    if not result.success:
        return f"Error: {result.error}"

    if not result.parsed_data:
        return "No login pages found via fuzzing."

    # Filter for likely login pages
    login_keywords = ["login", "signin", "sign-in", "auth", "admin", "user", "account", "portal", "sso", "oauth", "session", "wp-login", "wp-admin"]

    potential_logins = []
    other_findings = []

    for item in result.parsed_data:
        url = item.get("url", "").lower()
        input_val = item.get("input", "").lower()

        is_login = any(kw in url or kw in input_val for kw in login_keywords)
        if is_login:
            potential_logins.append(item)
        else:
            other_findings.append(item)

    output = f"Login page discovery results for {base_url}:\n\n"

    if potential_logins:
        output += f"POTENTIAL LOGIN PAGES ({len(potential_logins)}):\n"
        for item in potential_logins:
            output += f"  [{item.get('status')}] {item.get('url')}\n"

    if other_findings:
        output += f"\nOther interesting paths ({len(other_findings)}):\n"
        for item in other_findings[:10]:
            output += f"  [{item.get('status')}] {item.get('url')}\n"
        if len(other_findings) > 10:
            output += f"  ... and {len(other_findings) - 10} more\n"

    if not potential_logins and not other_findings:
        output += "No results found.\n"

    return output


@tool
def amass_subdomain_enum(domain: str, passive_only: bool = True) -> str:
    """Run amass to discover subdomains of a target domain.

    Use this to find additional attack surface - subdomains often have
    different security configurations or forgotten admin panels.

    Args:
        domain: Target domain (e.g., "example.com")
            Do NOT include protocol (http/https) or paths.
        passive_only: If True, only use passive sources (safer, no direct contact).
            If False, actively probe for subdomains (more thorough but detectable).

    Returns:
        List of discovered subdomains.
    """
    mode = "passive" if passive_only else "active"

    result = run_amass(domain=domain, mode=mode, timeout=300)

    if not result.success:
        return f"Error: {result.error}"

    if not result.parsed_data:
        return "No subdomains discovered."

    subdomains = result.parsed_data.get("subdomains", [])

    output = f"Amass subdomain enumeration for {domain}:\n\n"
    output += f"Found {len(subdomains)} subdomain(s):\n"

    # Categorize subdomains
    interesting_keywords = ["admin", "api", "dev", "test", "staging", "beta", "internal", "vpn", "mail", "portal", "login", "auth", "sso"]

    interesting = []
    regular = []

    for sub in subdomains:
        if any(kw in sub.lower() for kw in interesting_keywords):
            interesting.append(sub)
        else:
            regular.append(sub)

    if interesting:
        output += "\nINTERESTING SUBDOMAINS (potential targets):\n"
        for sub in interesting:
            output += f"  * {sub}\n"

    if regular:
        output += f"\nOther subdomains ({len(regular)}):\n"
        for sub in regular[:20]:
            output += f"  - {sub}\n"
        if len(regular) > 20:
            output += f"  ... and {len(regular) - 20} more\n"

    return output


@tool
def ffuf_api_discovery(base_url: str) -> str:
    """Run ffuf to discover API endpoints.

    Useful for finding REST APIs, GraphQL endpoints, and other
    programmatic interfaces that might have authentication bypasses.

    Args:
        base_url: Base URL to scan (e.g., "https://example.com" or "https://api.example.com")

    Returns:
        List of discovered API endpoints.
    """
    # Try to get API wordlist
    wordlist = get_ffuf_wordlist("api")
    if not wordlist:
        wordlist = get_ffuf_wordlist("directories")
    if not wordlist:
        return "Error: No wordlist found. Please ensure SecLists is installed."

    # Try common API base paths
    api_paths = ["/api/FUZZ", "/v1/FUZZ", "/v2/FUZZ", "/api/v1/FUZZ", "/api/v2/FUZZ"]

    all_results = []

    for api_path in api_paths[:2]:  # Limit to first 2 to save time
        target_url = f"{base_url.rstrip('/')}{api_path}"

        result = run_ffuf(
            target_url=target_url,
            wordlist=wordlist,
            mode="dir",
            extensions="",
            filters={"fc": "404,405"},
            timeout=120,
            rate=100,
        )

        if result.success and result.parsed_data:
            all_results.extend(result.parsed_data)

    if not all_results:
        return "No API endpoints discovered."

    output = f"API discovery results for {base_url}:\n\n"
    output += f"Found {len(all_results)} endpoint(s):\n"

    for item in all_results[:25]:
        output += f"  [{item.get('status')}] {item.get('url')}\n"

    if len(all_results) > 25:
        output += f"  ... and {len(all_results) - 25} more\n"

    return output
