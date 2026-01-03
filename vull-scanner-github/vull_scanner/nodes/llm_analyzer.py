"""LLM analyzer node for deciding next attack steps."""

import json
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langchain_core.tools import tool
from vull_scanner.state import ScannerState, LoginEndpoint
from vull_scanner.nodes.ffuf_scanner import identify_login_endpoints, identify_injectable_endpoints


SYSTEM_PROMPT = """You are a security analyst reviewing vulnerability scan results.

Based on the Nmap and FFUF scan results provided, analyze the findings and decide on the next attack steps.

## Your Tasks:
1. Identify potential SQL injection targets (URLs with parameters)
2. Identify login pages for credential brute-forcing
3. Note any other interesting findings

## Available Actions:
After analysis, you should output a JSON object with your findings:

```json
{
    "login_endpoints": [
        {
            "url": "https://example.com/login",
            "method": "POST",
            "username_field": "username",
            "password_field": "password"
        }
    ],
    "injectable_endpoints": [
        "https://example.com/page.php?id=1"
    ],
    "technologies_detected": ["wordpress", "mysql"],
    "attack_recommendations": [
        "Run Sqlmap on page.php?id parameter",
        "Brute-force admin login"
    ],
    "notes": "Additional observations..."
}
```

Be thorough in your analysis. Look for:
- URLs with query parameters (potential SQLi)
- Login/admin pages (credential attacks)
- Technology indicators (WordPress, Joomla, etc.)
- Interesting paths that might contain vulnerabilities
"""


def llm_analyzer_node(state: ScannerState) -> dict:
    """LLM analyzes Nmap and FFUF results to decide attack strategy.

    Args:
        state: Current scanner state with scan results.

    Returns:
        Updated state with login_endpoints and injectable_endpoints.
    """
    nmap_result = state.get("nmap_result")
    ffuf_results = state.get("ffuf_results", [])
    detected_technologies = state.get("detected_technologies", [])
    errors = list(state.get("errors", []))

    print("\n[*] LLM analyzing scan results...")

    # First, do automated detection
    auto_login_endpoints = identify_login_endpoints(ffuf_results)
    auto_injectable = identify_injectable_endpoints(ffuf_results)

    print(f"    Auto-detected {len(auto_login_endpoints)} potential login pages")
    print(f"    Auto-detected {len(auto_injectable)} potential SQLi targets")

    # Build context for LLM
    context = build_analysis_context(nmap_result, ffuf_results, detected_technologies)

    try:
        model = ChatOpenAI(model="gpt-4o", temperature=0, max_tokens=4096)

        response = model.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=context),
        ])

        # Parse LLM response
        llm_findings = parse_llm_response(response.content)

        # Merge auto-detected and LLM findings
        login_endpoints = merge_login_endpoints(
            auto_login_endpoints,
            llm_findings.get("login_endpoints", [])
        )
        injectable_endpoints = list(set(
            auto_injectable + llm_findings.get("injectable_endpoints", [])
        ))

        print(f"\n[+] Analysis complete:")
        print(f"    Login endpoints: {len(login_endpoints)}")
        for ep in login_endpoints:
            print(f"      - {ep.url}")
        print(f"    SQLi targets: {len(injectable_endpoints)}")
        for url in injectable_endpoints[:5]:
            print(f"      - {url}")
        if len(injectable_endpoints) > 5:
            print(f"      ... and {len(injectable_endpoints) - 5} more")

        # Determine next phase
        if injectable_endpoints or login_endpoints:
            next_phase = "attack"
        else:
            next_phase = "complete"

        return {
            "login_endpoints": login_endpoints,
            "injectable_endpoints": injectable_endpoints,
            "messages": [response],
            "current_phase": next_phase,
        }

    except Exception as e:
        print(f"[!] LLM analysis failed: {e}")
        errors.append(f"LLM analysis failed: {e}")

        # Fall back to auto-detected results
        login_endpoints = [
            LoginEndpoint(url=url, method="POST")
            for url in auto_login_endpoints
        ]

        return {
            "login_endpoints": login_endpoints,
            "injectable_endpoints": auto_injectable,
            "errors": errors,
            "current_phase": "attack" if (login_endpoints or auto_injectable) else "complete",
        }


def build_analysis_context(nmap_result, ffuf_results, technologies) -> str:
    """Build context string for LLM analysis.

    Args:
        nmap_result: NmapResult object.
        ffuf_results: List of FFUFScanResult objects.
        technologies: List of DetectedTechnology objects.

    Returns:
        Formatted context string.
    """
    context_parts = []

    # Nmap results
    if nmap_result:
        context_parts.append("## Nmap Scan Results\n")
        context_parts.append(f"Target: {nmap_result.target}\n")
        context_parts.append(f"Open Ports: {len(nmap_result.open_ports)}\n")
        for port in nmap_result.open_ports:
            context_parts.append(f"  - {port.port}/{port.protocol}: {port.service}")
            if port.version:
                context_parts.append(f" ({port.version})")
            context_parts.append("\n")
        if nmap_result.os_detection:
            context_parts.append(f"OS: {nmap_result.os_detection}\n")
        context_parts.append("\n")

    # FFUF results
    if ffuf_results:
        context_parts.append("## FFUF Discovery Results\n")
        for scan in ffuf_results:
            context_parts.append(f"\nWordlist: {scan.wordlist_used}\n")
            context_parts.append(f"Discovered paths ({len(scan.results)}):\n")
            for result in scan.results[:50]:  # Limit to 50 per wordlist
                context_parts.append(
                    f"  [{result.status_code}] {result.url} "
                    f"(len={result.content_length})\n"
                )
            if len(scan.results) > 50:
                context_parts.append(f"  ... and {len(scan.results) - 50} more\n")
        context_parts.append("\n")

    # Technologies
    if technologies:
        context_parts.append("## Detected Technologies\n")
        for tech in technologies:
            context_parts.append(f"  - {tech.name}")
            if tech.version:
                context_parts.append(f" {tech.version}")
            context_parts.append(f" ({tech.confidence}): {tech.evidence}\n")
        context_parts.append("\n")

    return "".join(context_parts)


def parse_llm_response(content: str) -> dict:
    """Parse LLM response JSON.

    Args:
        content: LLM response content.

    Returns:
        Parsed dictionary with findings.
    """
    try:
        # Find JSON block in response
        json_start = content.find("{")
        json_end = content.rfind("}") + 1

        if json_start != -1 and json_end > json_start:
            json_str = content[json_start:json_end]
            return json.loads(json_str)
    except (json.JSONDecodeError, ValueError):
        pass

    return {}


def merge_login_endpoints(auto_urls: list[str], llm_endpoints: list[dict]) -> list[LoginEndpoint]:
    """Merge auto-detected URLs with LLM-analyzed endpoints.

    Args:
        auto_urls: Auto-detected login URLs.
        llm_endpoints: LLM-analyzed endpoints with field info.

    Returns:
        List of LoginEndpoint objects.
    """
    endpoints = []
    seen_urls = set()

    # First, add LLM-analyzed endpoints (they have more info)
    for ep in llm_endpoints:
        url = ep.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            endpoints.append(LoginEndpoint(
                url=url,
                method=ep.get("method", "POST"),
                username_field=ep.get("username_field", "username"),
                password_field=ep.get("password_field", "password"),
                additional_fields=ep.get("additional_fields", {}),
            ))

    # Add auto-detected URLs that weren't in LLM results
    for url in auto_urls:
        if url not in seen_urls:
            seen_urls.add(url)
            endpoints.append(LoginEndpoint(
                url=url,
                method="POST",
            ))

    return endpoints


def should_run_sqlmap(state: ScannerState) -> bool:
    """Check if Sqlmap should be run.

    Args:
        state: Current scanner state.

    Returns:
        True if there are injectable endpoints.
    """
    return bool(state.get("injectable_endpoints"))


def should_run_bruteforce(state: ScannerState) -> bool:
    """Check if credential brute-force should be run.

    Args:
        state: Current scanner state.

    Returns:
        True if there are login endpoints.
    """
    return bool(state.get("login_endpoints"))
