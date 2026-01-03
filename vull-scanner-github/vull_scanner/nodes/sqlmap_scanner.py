"""Sqlmap scanner node for SQL injection testing."""

import json
import os
import re
import time
from vull_scanner.state import ScannerState, SqlmapResult, SqlInjection
from vull_scanner.utils.tool_runner import run_command, get_temp_dir, ToolNotFoundError, ToolExecutionError


def sqlmap_scanner_node(state: ScannerState) -> dict:
    """Run Sqlmap on identified injectable endpoints.

    Args:
        state: Current scanner state with injectable_endpoints.

    Returns:
        Updated state with sqlmap_results.
    """
    injectable_endpoints = state.get("injectable_endpoints", [])
    errors = list(state.get("errors", []))

    if not injectable_endpoints:
        print("[*] No injectable endpoints to test with Sqlmap")
        return {
            "sqlmap_results": [],
            "current_phase": "complete",
        }

    print(f"\n[*] Running Sqlmap on {len(injectable_endpoints)} endpoint(s)...")

    results = []

    for endpoint in injectable_endpoints:
        print(f"\n[*] Testing: {endpoint}")

        try:
            sqlmap_result = run_sqlmap(endpoint)
            results.append(sqlmap_result)

            if sqlmap_result.vulnerable:
                print(f"[+] VULNERABLE! Found {len(sqlmap_result.injections)} injection(s)")
                for inj in sqlmap_result.injections:
                    print(f"    - {inj.injection_type}: {inj.parameter}")
                if sqlmap_result.database_type:
                    print(f"    Database: {sqlmap_result.database_type}")
            else:
                print(f"[-] Not vulnerable")

        except ToolNotFoundError as e:
            errors.append(str(e))
            print(f"[!] {e}")
            break
        except ToolExecutionError as e:
            errors.append(f"Sqlmap failed on {endpoint}: {e}")
            print(f"[!] Sqlmap error: {e}")

    vulnerable_count = sum(1 for r in results if r.vulnerable)
    print(f"\n[+] Sqlmap completed: {vulnerable_count}/{len(results)} vulnerable")

    return {
        "sqlmap_results": results,
        "errors": errors if errors != list(state.get("errors", [])) else state.get("errors", []),
        "current_phase": "complete",
    }


def run_sqlmap(url: str) -> SqlmapResult:
    """Run Sqlmap on a single URL.

    Args:
        url: URL to test for SQL injection.

    Returns:
        SqlmapResult with findings.
    """
    output_dir = get_temp_dir()

    try:
        start_time = time.time()

        # Run Sqlmap with:
        # --batch: Non-interactive mode
        # --level=2: Increase test level
        # --risk=2: Increase risk level
        # --output-dir: Where to write results
        # --forms: Test forms if no parameters in URL
        # --smart: Smart mode - only test promising parameters
        # --threads=4: Use 4 threads
        result = run_command(
            [
                "sqlmap",
                "-u", url,
                "--batch",
                "--level=2",
                "--risk=2",
                "--output-dir", output_dir,
                "--forms",
                "--smart",
                "--threads=4",
            ],
            timeout=300,  # 5 minute timeout per URL
        )

        scan_time = time.time() - start_time

        # Parse results from output
        return parse_sqlmap_output(url, result.stdout, result.stderr, output_dir)

    finally:
        # Clean up temp directory
        cleanup_temp_dir(output_dir)


def parse_sqlmap_output(url: str, stdout: str, stderr: str, output_dir: str) -> SqlmapResult:
    """Parse Sqlmap output to extract findings.

    Args:
        url: URL that was tested.
        stdout: Sqlmap stdout.
        stderr: Sqlmap stderr.
        output_dir: Directory where Sqlmap wrote results.

    Returns:
        SqlmapResult with parsed findings.
    """
    injections = []
    database_type = ""
    databases_found = []
    tables_found = []
    vulnerable = False

    combined_output = stdout + stderr

    # Check for vulnerability indicators
    vuln_patterns = [
        r"is vulnerable",
        r"injectable",
        r"identified the following injection",
        r"Type: (\w+[-\s]*\w*)",  # Injection type
    ]

    for pattern in vuln_patterns[:3]:
        if re.search(pattern, combined_output, re.IGNORECASE):
            vulnerable = True
            break

    # Extract injection types
    injection_matches = re.finditer(
        r"Parameter: (\w+).*?Type: ([\w\s-]+?)(?:\n|Title:)",
        combined_output,
        re.DOTALL | re.IGNORECASE
    )

    for match in injection_matches:
        param = match.group(1)
        inj_type = match.group(2).strip()

        # Extract payload if available
        payload_match = re.search(
            rf"Parameter: {param}.*?Payload: ([^\n]+)",
            combined_output,
            re.DOTALL | re.IGNORECASE
        )
        payload = payload_match.group(1).strip() if payload_match else ""

        injections.append(SqlInjection(
            parameter=param,
            injection_type=inj_type,
            payload=payload,
            dbms=database_type,
        ))

    # Alternative injection detection
    if not injections and vulnerable:
        # Try simpler pattern matching
        param_match = re.search(r"Parameter: (\w+)", combined_output)
        type_match = re.search(r"Type: ([\w\s-]+)", combined_output)

        if param_match:
            injections.append(SqlInjection(
                parameter=param_match.group(1),
                injection_type=type_match.group(1).strip() if type_match else "unknown",
                payload="",
                dbms=database_type,
            ))

    # Extract database type
    dbms_patterns = [
        r"back-end DBMS: (\w+)",
        r"DBMS: (\w+)",
        r"database management system: (\w+)",
    ]

    for pattern in dbms_patterns:
        match = re.search(pattern, combined_output, re.IGNORECASE)
        if match:
            database_type = match.group(1)
            break

    # Update injections with DBMS
    for inj in injections:
        if not inj.dbms and database_type:
            inj.dbms = database_type

    # Extract database names
    db_match = re.search(r"available databases \[\d+\]:\s*((?:\[\*\] \w+\n?)+)", combined_output)
    if db_match:
        databases_found = re.findall(r"\[\*\] (\w+)", db_match.group(1))

    # Check output directory for additional info
    try:
        log_file = find_sqlmap_log(output_dir)
        if log_file:
            with open(log_file, "r", errors="ignore") as f:
                log_content = f.read()
                # Parse log for additional findings
                if not database_type:
                    for pattern in dbms_patterns:
                        match = re.search(pattern, log_content, re.IGNORECASE)
                        if match:
                            database_type = match.group(1)
                            break
    except OSError:
        pass

    return SqlmapResult(
        target_url=url,
        vulnerable=vulnerable or bool(injections),
        injections=injections,
        database_type=database_type,
        databases_found=databases_found,
        tables_found=tables_found,
        raw_output=combined_output[:5000],  # Truncate for storage
    )


def find_sqlmap_log(output_dir: str) -> str | None:
    """Find the Sqlmap log file in output directory.

    Args:
        output_dir: Sqlmap output directory.

    Returns:
        Path to log file or None.
    """
    try:
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                if file == "log":
                    return os.path.join(root, file)
    except OSError:
        pass
    return None


def cleanup_temp_dir(path: str) -> None:
    """Remove temporary directory and contents.

    Args:
        path: Directory path to remove.
    """
    try:
        import shutil
        shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass
