"""Result printer node for outputting scan results."""

from vull_scanner.state import ScannerState


def mask_password(password: str, show_full: bool = False) -> str:
    """Mask a password for safe display.

    Args:
        password: The password to mask.
        show_full: If True, show the full password (for --show-passwords flag).

    Returns:
        Masked or full password depending on show_full flag.
    """
    if show_full:
        return password
    if not password:
        return "****"
    if len(password) <= 2:
        return "*" * len(password)
    # Show first and last character with asterisks in between
    return f"{password[0]}{'*' * (len(password) - 2)}{password[-1]}"


def result_printer_node(state: ScannerState) -> dict:
    """Print the scan results to stdout.

    Args:
        state: Final scanner state with all results.

    Returns:
        Empty dict (no state updates).
    """
    print("\n" + "=" * 60)
    print("VULNERABILITY SCAN RESULTS")
    print("=" * 60)

    # Target info
    print(f"\nTarget: {state['target_url']}")

    # Port scan results
    port_scan = state.get("port_scan")
    if port_scan:
        print("\nPort Scan:")
        print(f"  Port 80 (HTTP):   {'OPEN' if port_scan.port_80_open else 'CLOSED'}")
        print(f"  Port 443 (HTTPS): {'OPEN' if port_scan.port_443_open else 'CLOSED'}")
        if port_scan.preferred_protocol:
            print(f"  Protocol Used:    {port_scan.preferred_protocol.upper()}")

    # Discovered subdomains
    subdomains = state.get("discovered_subdomains", [])
    if subdomains:
        print(f"\nDiscovered Subdomains: {len(subdomains)}")
        for sub in subdomains[:10]:
            print(f"  - {sub}")
        if len(subdomains) > 10:
            print(f"  ... and {len(subdomains) - 10} more")

    # Detected technologies
    technologies = state.get("detected_technologies", [])
    if technologies:
        print(f"\nDetected Technologies: {len(technologies)}")
        for tech in technologies:
            print(f"  - {tech.name} ({tech.confidence} confidence)")
            print(f"    Evidence: {tech.evidence[:80]}...")

    # Wordlists used
    wordlist_selection = state.get("wordlist_selection")
    if wordlist_selection:
        print(f"\nWordlist Selection:")
        print(f"  Reasoning: {wordlist_selection.reasoning}")
        print(f"  Username files: {len(wordlist_selection.username_files)}")
        for f in wordlist_selection.username_files[:3]:
            print(f"    - {f.split('/')[-1]}")
        if len(wordlist_selection.username_files) > 3:
            print(f"    ... and {len(wordlist_selection.username_files) - 3} more")
        print(f"  Password files: {len(wordlist_selection.password_files)}")
        for f in wordlist_selection.password_files[:3]:
            print(f"    - {f.split('/')[-1]}")
        if len(wordlist_selection.password_files) > 3:
            print(f"    ... and {len(wordlist_selection.password_files) - 3} more")

    # Login endpoints
    endpoints = state.get("login_endpoints", [])
    print(f"\nLogin Endpoints Found: {len(endpoints)}")
    for i, ep in enumerate(endpoints, 1):
        print(f"\n  [{i}] {ep.url}")
        print(f"      Method: {ep.method}")
        print(f"      Fields: {', '.join(ep.form_fields)}")
        if ep.csrf_field:
            print(f"      CSRF:   {ep.csrf_field}")

    # Credential test results
    results = state.get("credential_results", [])
    successful = [r for r in results if r.success]

    print(f"\nCredential Testing:")
    print(f"  Total Attempts: {len(results)}")
    print(f"  Successful:     {len(successful)}")

    if successful:
        show_passwords = state.get("show_passwords", False)
        print("\n" + "*" * 40)
        print("*** VALID CREDENTIALS FOUND ***")
        print("*" * 40)
        if not show_passwords:
            print("  (Passwords masked - use --show-passwords to reveal)")
        for r in successful:
            print(f"\n  Endpoint: {r.endpoint_url}")
            print(f"  Username: {r.username}")
            print(f"  Password: {mask_password(r.password, show_passwords)}")
            print(f"  Evidence: {r.evidence}")
    elif results:
        print("\n  No valid credentials found.")

    # Errors
    errors = state.get("errors", [])
    if errors:
        print("\nErrors Encountered:")
        for err in errors:
            print(f"  - {err}")

    print("\n" + "=" * 60)

    return {}
