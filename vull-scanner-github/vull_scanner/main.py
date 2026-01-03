"""CLI entry point for the vulnerability scanner."""

import argparse
import sys
import os
import warnings


def main():
    """Main entry point for the vulnerability scanner CLI."""
    parser = argparse.ArgumentParser(
        description="LangGraph-based Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python -m vull_scanner example.com
    python -m vull_scanner https://example.com
    python -m vull_scanner example.com --verbose

Environment:
    OPENAI_API_KEY       Required. Your OpenAI API key.

SecLists:
    The scanner expects SecLists to be installed at one of:
    - /usr/share/seclists
    - ~/SecLists
    - /opt/seclists

    If not found, default credential lists will be used.
        """,
    )

    parser.add_argument(
        "target",
        help="Target URL or hostname to scan (e.g., example.com)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output (show node transitions)",
    )
    parser.add_argument(
        "--threads",
        "-t",
        type=int,
        default=5,
        help="Initial number of threads for parallel scanning (default: 5)",
    )
    parser.add_argument(
        "--max-threads",
        type=int,
        default=50,
        help="Maximum threads for adaptive scaling (default: 50)",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow scanning private/internal IP ranges (disabled by default for SSRF protection)",
    )
    parser.add_argument(
        "--show-passwords",
        action="store_true",
        help="Show passwords in plain text in output (masked by default)",
    )
    parser.add_argument(
        "--skip-ssl-verify",
        action="store_true",
        help="Skip SSL certificate verification (not recommended)",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Path to log file for JSON-formatted logs",
    )

    args = parser.parse_args()

    # Check for OPENAI_API_KEY
    if not os.environ.get("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY environment variable not set")
        print()
        print("Please set it with:")
        print("    export OPENAI_API_KEY=your-key-here")
        print()
        print("Get an API key at: https://platform.openai.com/api-keys")
        sys.exit(1)

    # Initialize logging early
    from vull_scanner.utils.logging import setup_logging
    logger = setup_logging(verbose=args.verbose, log_file=args.log_file)

    # Configure SSL verification via environment (picked up by http_client and credential_tester)
    if args.skip_ssl_verify:
        os.environ["VULL_SKIP_SSL_VERIFY"] = "true"
        # Suppress SSL warnings only when explicitly requested
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        logger.warning("SSL certificate verification disabled - use with caution")

    # Import here to avoid loading heavy dependencies for --help
    from vull_scanner.graph import compile_scanner
    from vull_scanner.state import ScannerState

    # Print banner
    print()
    print("=" * 50)
    print("  VULL-SCANNER - LangGraph Vulnerability Scanner")
    print("=" * 50)
    print()
    print("[!] WARNING: Only use this tool on systems you have")
    print("    explicit permission to test. Unauthorized access")
    print("    to computer systems is illegal.")
    print()

    # Compile the graph
    scanner = compile_scanner()

    # Check for external tools
    from vull_scanner.utils.external_tools import get_available_tools
    tools_available = get_available_tools()
    print("[*] External tools available:")
    for tool, available in tools_available.items():
        status = "YES" if available else "NO"
        print(f"    - {tool}: {status}")
    print()

    # Set thread configuration via environment (picked up by credential_tester)
    os.environ["VULL_MIN_THREADS"] = str(args.threads)
    os.environ["VULL_MAX_THREADS"] = str(args.max_threads)

    print(f"[*] Threading: {args.threads} initial, {args.max_threads} max (adaptive scaling)")

    # Initialize state
    initial_state: ScannerState = {
        "target_url": args.target,
        "allow_private": args.allow_private,
        "show_passwords": args.show_passwords,
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

    print(f"[*] Target: {args.target}")
    print("-" * 50)

    # Run the scanner
    final_state = None
    try:
        if args.verbose:
            # Stream events for verbose mode
            for event in scanner.stream(initial_state):
                for node_name, output in event.items():
                    if node_name != "__end__":
                        print(f"\n[DEBUG] Node '{node_name}' completed")
                        final_state = output
        else:
            # Just invoke and wait for results
            final_state = scanner.invoke(initial_state)

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)

    # Report any errors that occurred
    if final_state and final_state.get("errors"):
        print("\n[!] Errors encountered during scan:")
        for error in final_state["errors"]:
            print(f"    - {error}")

    print("\n[*] Scan complete")


if __name__ == "__main__":
    main()
