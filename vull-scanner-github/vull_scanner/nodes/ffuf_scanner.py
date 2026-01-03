"""FFUF scanner node for directory and endpoint fuzzing."""

import json
import os
import time
from vull_scanner.state import (
    ScannerState,
    FFUFResult,
    FFUFScanResult,
    DetectedTechnology,
)
from vull_scanner.utils.tool_runner import run_command, get_temp_file, ToolNotFoundError
from vull_scanner.nodes.nmap_scanner import get_http_ports


# SecLists paths for different wordlists
SECLISTS_BASE = "/usr/share/seclists"
WORDLISTS = {
    "common": f"{SECLISTS_BASE}/Discovery/Web-Content/common.txt",
    "directories": f"{SECLISTS_BASE}/Discovery/Web-Content/directory-list-2.3-small.txt",
    "raft_dirs": f"{SECLISTS_BASE}/Discovery/Web-Content/raft-medium-directories.txt",
    "raft_files": f"{SECLISTS_BASE}/Discovery/Web-Content/raft-medium-files.txt",
    "quickhits": f"{SECLISTS_BASE}/Discovery/Web-Content/quickhits.txt",
    "login_pages": f"{SECLISTS_BASE}/Discovery/Web-Content/LoginPages.txt",
    # CMS specific
    "wordpress": f"{SECLISTS_BASE}/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
    "joomla": f"{SECLISTS_BASE}/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt",
    "drupal": f"{SECLISTS_BASE}/Discovery/Web-Content/CMS/drupal.fuzz.txt",
    # Tomcat
    "tomcat": f"{SECLISTS_BASE}/Discovery/Web-Content/tomcat.txt",
}


def ffuf_scanner_node(state: ScannerState) -> dict:
    """Run FFUF for directory and endpoint discovery.

    Selects wordlists based on detected technologies from Nmap.

    Args:
        state: Current scanner state with nmap_result.

    Returns:
        Updated state with ffuf_results.
    """
    nmap_result = state.get("nmap_result")
    detected_technologies = list(state.get("detected_technologies", []))
    errors = list(state.get("errors", []))

    if not nmap_result:
        errors.append("No Nmap results available for FFUF scanning")
        return {
            "ffuf_results": [],
            "errors": errors,
            "current_phase": "analysis",
        }

    # Get HTTP ports to scan
    http_ports = get_http_ports(nmap_result)

    if not http_ports:
        print("[!] No HTTP/HTTPS ports found, skipping FFUF")
        errors.append("No HTTP/HTTPS ports found")
        return {
            "ffuf_results": [],
            "errors": errors,
            "current_phase": "analysis",
        }

    print(f"\n[*] Running FFUF on {len(http_ports)} HTTP port(s)...")

    # Select wordlists based on detected technologies
    wordlists_to_use = select_wordlists(detected_technologies)
    print(f"    Using {len(wordlists_to_use)} wordlist(s)")

    all_results = []

    for port, protocol in http_ports:
        base_url = f"{protocol}://{nmap_result.target}"
        if not (protocol == "http" and port == 80) and not (protocol == "https" and port == 443):
            base_url = f"{base_url}:{port}"

        print(f"\n[*] Fuzzing {base_url}")

        for wordlist_name, wordlist_path in wordlists_to_use:
            if not os.path.exists(wordlist_path):
                print(f"    [!] Wordlist not found: {wordlist_path}")
                continue

            try:
                scan_result = run_ffuf(base_url, wordlist_path, wordlist_name)
                if scan_result.results:
                    all_results.append(scan_result)
                    print(f"    [{wordlist_name}] Found {len(scan_result.results)} results")

                    # Detect technologies from discovered paths
                    new_techs = detect_technologies_from_ffuf(scan_result.results)
                    for tech in new_techs:
                        if tech.name not in [t.name for t in detected_technologies]:
                            detected_technologies.append(tech)

            except ToolNotFoundError as e:
                errors.append(str(e))
                print(f"    [!] {e}")
                break

    print(f"\n[+] FFUF completed: {sum(len(r.results) for r in all_results)} total discoveries")

    return {
        "ffuf_results": all_results,
        "detected_technologies": detected_technologies,
        "current_phase": "analysis",
    }


def run_ffuf(base_url: str, wordlist_path: str, wordlist_name: str) -> FFUFScanResult:
    """Run FFUF with a single wordlist.

    Args:
        base_url: Base URL to fuzz (e.g., https://example.com)
        wordlist_path: Path to wordlist file.
        wordlist_name: Name of the wordlist for logging.

    Returns:
        FFUFScanResult with discovered endpoints.
    """
    output_file = get_temp_file(".json")

    try:
        start_time = time.time()

        # Run FFUF
        # -u: URL with FUZZ keyword
        # -w: Wordlist
        # -o: Output file
        # -of: Output format (json)
        # -mc: Match status codes
        # -fc: Filter status codes
        # -s: Silent mode
        # -t: Threads
        # -timeout: Request timeout
        result = run_command(
            [
                "ffuf",
                "-u", f"{base_url}/FUZZ",
                "-w", wordlist_path,
                "-o", output_file,
                "-of", "json",
                "-mc", "200,201,204,301,302,307,401,403,405,500",
                "-fc", "404",
                "-s",
                "-t", "50",
                "-timeout", "10",
            ],
            timeout=300,  # 5 minute timeout per wordlist
        )

        scan_time = time.time() - start_time

        # Parse results
        results = parse_ffuf_json(output_file)

        return FFUFScanResult(
            base_url=base_url,
            wordlist_used=wordlist_name,
            results=results,
            total_requests=count_wordlist_lines(wordlist_path),
            scan_time=scan_time,
        )

    finally:
        # Clean up temp file
        if os.path.exists(output_file):
            os.remove(output_file)


def parse_ffuf_json(json_path: str) -> list[FFUFResult]:
    """Parse FFUF JSON output.

    Args:
        json_path: Path to FFUF JSON output file.

    Returns:
        List of FFUFResult objects.
    """
    results = []

    if not os.path.exists(json_path):
        return results

    try:
        with open(json_path, "r") as f:
            data = json.load(f)

        for item in data.get("results", []):
            result = FFUFResult(
                url=item.get("url", ""),
                status_code=item.get("status", 0),
                content_length=item.get("length", 0),
                content_words=item.get("words", 0),
                content_lines=item.get("lines", 0),
                redirect_location=item.get("redirectlocation", ""),
            )
            results.append(result)

    except (json.JSONDecodeError, KeyError) as e:
        print(f"    [!] Failed to parse FFUF output: {e}")

    return results


def select_wordlists(technologies: list[DetectedTechnology]) -> list[tuple[str, str]]:
    """Select wordlists based on detected technologies.

    Args:
        technologies: List of detected technologies.

    Returns:
        List of (name, path) tuples for wordlists to use.
    """
    wordlists = []
    tech_names = [t.name.lower() for t in technologies]

    # Always use common and login pages
    if os.path.exists(WORDLISTS["common"]):
        wordlists.append(("common", WORDLISTS["common"]))
    if os.path.exists(WORDLISTS["login_pages"]):
        wordlists.append(("login_pages", WORDLISTS["login_pages"]))

    # Add technology-specific wordlists
    if "tomcat" in tech_names:
        if os.path.exists(WORDLISTS["tomcat"]):
            wordlists.append(("tomcat", WORDLISTS["tomcat"]))

    if "wordpress" in tech_names:
        if os.path.exists(WORDLISTS["wordpress"]):
            wordlists.append(("wordpress", WORDLISTS["wordpress"]))

    if "joomla" in tech_names:
        if os.path.exists(WORDLISTS["joomla"]):
            wordlists.append(("joomla", WORDLISTS["joomla"]))

    if "drupal" in tech_names:
        if os.path.exists(WORDLISTS["drupal"]):
            wordlists.append(("drupal", WORDLISTS["drupal"]))

    # Add quickhits for quick comprehensive scan
    if os.path.exists(WORDLISTS["quickhits"]):
        wordlists.append(("quickhits", WORDLISTS["quickhits"]))

    return wordlists


def detect_technologies_from_ffuf(results: list[FFUFResult]) -> list[DetectedTechnology]:
    """Detect technologies from FFUF discovered paths.

    Args:
        results: List of FFUF results.

    Returns:
        List of detected technologies.
    """
    technologies = []
    seen = set()

    for result in results:
        url_lower = result.url.lower()

        # WordPress detection
        if any(wp in url_lower for wp in ["wp-admin", "wp-content", "wp-includes", "wp-login"]):
            if "wordpress" not in seen:
                seen.add("wordpress")
                technologies.append(DetectedTechnology(
                    name="wordpress",
                    confidence="high",
                    evidence=f"Found WordPress path: {result.url}",
                ))

        # Joomla detection
        if any(j in url_lower for j in ["/administrator", "/components/com_"]):
            if "joomla" not in seen:
                seen.add("joomla")
                technologies.append(DetectedTechnology(
                    name="joomla",
                    confidence="high",
                    evidence=f"Found Joomla path: {result.url}",
                ))

        # Drupal detection
        if any(d in url_lower for d in ["/sites/default", "/modules/", "drupal"]):
            if "drupal" not in seen:
                seen.add("drupal")
                technologies.append(DetectedTechnology(
                    name="drupal",
                    confidence="high",
                    evidence=f"Found Drupal path: {result.url}",
                ))

        # Tomcat detection
        if any(t in url_lower for t in ["/manager", "/host-manager"]):
            if "tomcat" not in seen:
                seen.add("tomcat")
                technologies.append(DetectedTechnology(
                    name="tomcat",
                    confidence="high",
                    evidence=f"Found Tomcat path: {result.url}",
                ))

        # phpMyAdmin detection
        if "phpmyadmin" in url_lower or "pma" in url_lower:
            if "phpmyadmin" not in seen:
                seen.add("phpmyadmin")
                technologies.append(DetectedTechnology(
                    name="phpmyadmin",
                    confidence="high",
                    evidence=f"Found phpMyAdmin: {result.url}",
                ))

    return technologies


def count_wordlist_lines(path: str) -> int:
    """Count lines in a wordlist file.

    Args:
        path: Path to wordlist.

    Returns:
        Number of lines (approximate).
    """
    try:
        with open(path, "r", errors="ignore") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def identify_login_endpoints(ffuf_results: list[FFUFScanResult]) -> list[str]:
    """Identify potential login endpoints from FFUF results.

    Args:
        ffuf_results: List of FFUF scan results.

    Returns:
        List of URLs that look like login pages.
    """
    login_keywords = [
        "login", "signin", "sign-in", "auth", "authenticate",
        "admin", "administrator", "user", "account", "session",
        "wp-login", "wp-admin", "manager", "console",
    ]

    login_urls = []
    seen = set()

    for scan in ffuf_results:
        for result in scan.results:
            url_lower = result.url.lower()

            # Check if URL contains login-related keywords
            if any(kw in url_lower for kw in login_keywords):
                # Only include 200 or redirect responses
                if result.status_code in [200, 301, 302, 307]:
                    if result.url not in seen:
                        seen.add(result.url)
                        login_urls.append(result.url)

    return login_urls


def identify_injectable_endpoints(ffuf_results: list[FFUFScanResult]) -> list[str]:
    """Identify potential SQL injection targets from FFUF results.

    Looks for URLs with parameters or dynamic-looking paths.

    Args:
        ffuf_results: List of FFUF scan results.

    Returns:
        List of URLs that might be vulnerable to SQLi.
    """
    injectable_keywords = [
        "id=", "page=", "cat=", "item=", "product=", "article=",
        "view=", "file=", "download=", "show=", "content=",
        ".php?", ".asp?", ".aspx?", ".jsp?",
    ]

    injectable_urls = []
    seen = set()

    for scan in ffuf_results:
        for result in scan.results:
            url_lower = result.url.lower()

            # Check for parameter-like patterns
            if any(kw in url_lower for kw in injectable_keywords):
                if result.url not in seen:
                    seen.add(result.url)
                    injectable_urls.append(result.url)

    return injectable_urls
