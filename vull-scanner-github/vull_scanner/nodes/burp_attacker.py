"""Credential brute-forcing node using FFUF (Burp alternative).

Since Burp Suite requires a GUI and license for automation,
we use FFUF for POST request fuzzing with credential wordlists.
"""

import json
import os
import time
from vull_scanner.state import ScannerState, BurpResult, CredentialResult, LoginEndpoint
from vull_scanner.utils.tool_runner import run_command, get_temp_file, ToolNotFoundError, ToolExecutionError


# SecLists paths for credential wordlists
SECLISTS_BASE = "/usr/share/seclists"
CREDENTIAL_WORDLISTS = {
    "usernames": {
        "top": f"{SECLISTS_BASE}/Usernames/top-usernames-shortlist.txt",
        "common": f"{SECLISTS_BASE}/Usernames/Names/names.txt",
        "admin": f"{SECLISTS_BASE}/Usernames/cirt-default-usernames.txt",
    },
    "passwords": {
        "top": f"{SECLISTS_BASE}/Passwords/Common-Credentials/top-passwords-shortlist.txt",
        "common": f"{SECLISTS_BASE}/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
        "default": f"{SECLISTS_BASE}/Passwords/Default-Credentials/default-passwords.txt",
    },
}


def burp_attacker_node(state: ScannerState) -> dict:
    """Run credential brute-forcing on login endpoints using FFUF.

    Args:
        state: Current scanner state with login_endpoints.

    Returns:
        Updated state with burp_results.
    """
    login_endpoints = state.get("login_endpoints", [])
    detected_technologies = state.get("detected_technologies", [])
    errors = list(state.get("errors", []))

    if not login_endpoints:
        print("[*] No login endpoints to test for credentials")
        return {
            "burp_results": [],
            "current_phase": "complete",
        }

    print(f"\n[*] Running credential attack on {len(login_endpoints)} endpoint(s)...")

    # Select wordlists based on technologies
    userlist, passlist = select_credential_wordlists(detected_technologies)

    if not userlist or not passlist:
        errors.append("Credential wordlists not found")
        print("[!] Credential wordlists not found in SecLists")
        return {
            "burp_results": [],
            "errors": errors,
            "current_phase": "complete",
        }

    print(f"    Using userlist: {os.path.basename(userlist)}")
    print(f"    Using passlist: {os.path.basename(passlist)}")

    results = []

    for endpoint in login_endpoints:
        print(f"\n[*] Testing: {endpoint.url}")

        try:
            burp_result = run_credential_ffuf(endpoint, userlist, passlist)
            results.append(burp_result)

            if burp_result.successful_logins:
                print(f"[+] FOUND {len(burp_result.successful_logins)} valid credential(s)!")
                for cred in burp_result.successful_logins:
                    print(f"    - {cred.username}:{cred.password}")
            else:
                print(f"[-] No valid credentials found ({burp_result.total_attempts} attempts)")

        except ToolNotFoundError as e:
            errors.append(str(e))
            print(f"[!] {e}")
            break
        except ToolExecutionError as e:
            errors.append(f"Credential attack failed on {endpoint.url}: {e}")
            print(f"[!] Error: {e}")

    success_count = sum(len(r.successful_logins) for r in results)
    print(f"\n[+] Credential testing completed: {success_count} valid credential(s) found")

    return {
        "burp_results": results,
        "errors": errors if errors != list(state.get("errors", [])) else state.get("errors", []),
        "current_phase": "complete",
    }


def select_credential_wordlists(technologies: list) -> tuple[str, str]:
    """Select appropriate credential wordlists based on detected technologies.

    Args:
        technologies: List of DetectedTechnology objects.

    Returns:
        Tuple of (userlist_path, passlist_path).
    """
    tech_names = [t.name.lower() for t in technologies]

    # Default to top/common lists
    userlist = None
    passlist = None

    # Check for admin-related technologies
    admin_techs = ["tomcat", "phpmyadmin", "wordpress", "joomla", "drupal"]
    has_admin = any(t in tech_names for t in admin_techs)

    # Select userlist
    if has_admin and os.path.exists(CREDENTIAL_WORDLISTS["usernames"]["admin"]):
        userlist = CREDENTIAL_WORDLISTS["usernames"]["admin"]
    elif os.path.exists(CREDENTIAL_WORDLISTS["usernames"]["top"]):
        userlist = CREDENTIAL_WORDLISTS["usernames"]["top"]
    elif os.path.exists(CREDENTIAL_WORDLISTS["usernames"]["common"]):
        userlist = CREDENTIAL_WORDLISTS["usernames"]["common"]

    # Select passlist
    if has_admin and os.path.exists(CREDENTIAL_WORDLISTS["passwords"]["default"]):
        passlist = CREDENTIAL_WORDLISTS["passwords"]["default"]
    elif os.path.exists(CREDENTIAL_WORDLISTS["passwords"]["top"]):
        passlist = CREDENTIAL_WORDLISTS["passwords"]["top"]
    elif os.path.exists(CREDENTIAL_WORDLISTS["passwords"]["common"]):
        passlist = CREDENTIAL_WORDLISTS["passwords"]["common"]

    return userlist, passlist


def run_credential_ffuf(
    endpoint: LoginEndpoint,
    userlist: str,
    passlist: str,
) -> BurpResult:
    """Run FFUF for credential brute-forcing.

    Args:
        endpoint: Login endpoint to test.
        userlist: Path to username wordlist.
        passlist: Path to password wordlist.

    Returns:
        BurpResult with findings.
    """
    output_file = get_temp_file(".json")

    try:
        start_time = time.time()

        # Build POST data with FUZZ keywords
        username_field = endpoint.username_field or "username"
        password_field = endpoint.password_field or "password"

        # Add any additional fields
        post_data_parts = [
            f"{username_field}=UFUZZ",
            f"{password_field}=PFUZZ",
        ]
        for field, value in endpoint.additional_fields.items():
            post_data_parts.append(f"{field}={value}")

        post_data = "&".join(post_data_parts)

        # Determine target URL (use form_action if specified)
        target_url = endpoint.form_action if endpoint.form_action else endpoint.url

        # Run FFUF with clusterbomb mode (all combinations)
        # -X POST: Use POST method
        # -d: POST data
        # -w: Wordlists with UFUZZ and PFUZZ keywords
        # -mode clusterbomb: Try all username/password combinations
        # -mc: Match status codes (200, 302 often indicate success)
        # -fc: Filter common failure codes
        # -fs: Filter by response size (if baseline established)
        result = run_command(
            [
                "ffuf",
                "-u", target_url,
                "-X", endpoint.method,
                "-d", post_data,
                "-w", f"{userlist}:UFUZZ",
                "-w", f"{passlist}:PFUZZ",
                "-mode", "clusterbomb",
                "-mc", "200,302,303",
                "-o", output_file,
                "-of", "json",
                "-s",
                "-t", "20",  # 20 threads
                "-timeout", "10",
                "-H", "Content-Type: application/x-www-form-urlencoded",
            ],
            timeout=600,  # 10 minute timeout
        )

        scan_time = time.time() - start_time

        # Parse results
        successful_logins = parse_credential_results(output_file, username_field, password_field)

        # Count total attempts
        total_attempts = count_wordlist_lines(userlist) * count_wordlist_lines(passlist)

        return BurpResult(
            endpoint_url=endpoint.url,
            attack_type="ffuf_creds",
            total_attempts=total_attempts,
            successful_logins=successful_logins,
            raw_output=result.stdout[:2000],
        )

    finally:
        # Clean up temp file
        if os.path.exists(output_file):
            os.remove(output_file)


def parse_credential_results(
    json_path: str,
    username_field: str,
    password_field: str,
) -> list[CredentialResult]:
    """Parse FFUF JSON output for successful logins.

    Args:
        json_path: Path to FFUF JSON output.
        username_field: Name of username field.
        password_field: Name of password field.

    Returns:
        List of successful CredentialResult objects.
    """
    results = []

    if not os.path.exists(json_path):
        return results

    try:
        with open(json_path, "r") as f:
            data = json.load(f)

        for item in data.get("results", []):
            # Extract username and password from input
            input_data = item.get("input", {})
            username = input_data.get("UFUZZ", "")
            password = input_data.get("PFUZZ", "")

            # Determine if this is likely a success
            status = item.get("status", 0)
            length = item.get("length", 0)

            # Success indicators
            # - Status 302/303 (redirect after login)
            # - Status 200 with different response length
            is_success = status in [200, 302, 303]

            if is_success:
                results.append(CredentialResult(
                    endpoint_url=item.get("url", ""),
                    username=username,
                    password=password,
                    success=True,
                    status_code=status,
                    response_length=length,
                    evidence=f"Status {status}, Length {length}",
                ))

    except (json.JSONDecodeError, KeyError) as e:
        print(f"    [!] Failed to parse credential results: {e}")

    return results


def count_wordlist_lines(path: str) -> int:
    """Count lines in a wordlist file.

    Args:
        path: Path to wordlist.

    Returns:
        Number of lines.
    """
    try:
        with open(path, "r", errors="ignore") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def filter_false_positives(
    results: list[CredentialResult],
    baseline_length: int | None = None,
) -> list[CredentialResult]:
    """Filter out likely false positives from credential results.

    Args:
        results: List of credential results to filter.
        baseline_length: Response length for failed login (if known).

    Returns:
        Filtered list of likely true positives.
    """
    if not results:
        return results

    # If we have many results with same length, likely false positives
    length_counts = {}
    for r in results:
        length_counts[r.response_length] = length_counts.get(r.response_length, 0) + 1

    # Find the most common length (likely the failure response)
    common_length = max(length_counts, key=length_counts.get)
    common_count = length_counts[common_length]

    # If more than 50% have same length, filter them out
    if common_count > len(results) * 0.5:
        filtered = [r for r in results if r.response_length != common_length]
        if filtered:
            return filtered

    return results
