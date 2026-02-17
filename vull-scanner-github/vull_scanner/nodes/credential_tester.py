"""Credential tester node for testing login endpoints with SecLists wordlists."""

import os
import time
import httpx
import threading
import itertools
from vull_scanner.state import ScannerState, CredentialTestResult, LoginEndpoint
from vull_scanner.utils.seclists import (
    load_multiple_wordlists,
    get_wordlists_for_technologies,
    DEFAULT_USERNAMES,
    DEFAULT_PASSWORDS,
)
from vull_scanner.utils.thread_manager import AdaptiveThreadPool, ThreadConfig
from vull_scanner.utils.http_client import get_ssl_verify
from vull_scanner.utils.logging import get_logger

logger = get_logger("credential_tester")

# Configurable limits
MAX_USERNAMES_PER_FILE = 100
MAX_PASSWORDS_PER_FILE = 200
TOTAL_USERNAME_LIMIT = 500
TOTAL_PASSWORD_LIMIT = 1000
REQUEST_TIMEOUT = 10.0
REQUEST_DELAY = 0.1  # Reduced delay for parallel execution

# Threading configuration (can be overridden via environment)
SCALE_INTERVAL = 30.0  # Seconds between scaling checks


def get_thread_config() -> tuple[int, int]:
    """Get thread configuration from environment or defaults."""
    min_threads = int(os.environ.get("VULL_MIN_THREADS", "5"))
    max_threads = int(os.environ.get("VULL_MAX_THREADS", "50"))
    return min_threads, max_threads


def credential_tester_node(state: ScannerState) -> dict:
    """Test credentials against discovered login endpoints.

    Uses dynamically selected SecLists wordlists based on detected technologies
    to test username/password combinations against each discovered login form.

    Args:
        state: Scanner state with login_endpoints and wordlist_selection.

    Returns:
        Updated state with credential_results.
    """
    endpoints = state.get("login_endpoints", [])
    base_url = state["port_scan"].base_url
    wordlist_selection = state.get("wordlist_selection")
    detected_technologies = state.get("detected_technologies", [])
    errors = list(state.get("errors", []))

    if not endpoints:
        errors.append("No login endpoints to test")
        return {
            "credential_results": [],
            "current_phase": "complete",
            "errors": errors,
        }

    # Load wordlists based on selection or detected technologies
    print(f"\n[*] Loading wordlists based on detected technologies...")

    if wordlist_selection and (wordlist_selection.username_files or wordlist_selection.password_files):
        # Use the pre-selected wordlists
        print(f"    Using {len(wordlist_selection.username_files)} username files")
        print(f"    Using {len(wordlist_selection.password_files)} password files")

        usernames = load_multiple_wordlists(
            wordlist_selection.username_files,
            limit_per_file=MAX_USERNAMES_PER_FILE,
            total_limit=TOTAL_USERNAME_LIMIT,
        )
        passwords = load_multiple_wordlists(
            wordlist_selection.password_files,
            limit_per_file=MAX_PASSWORDS_PER_FILE,
            total_limit=TOTAL_PASSWORD_LIMIT,
        )

        # Print which files are being used
        print(f"\n    Username wordlists:")
        for f in wordlist_selection.username_files[:5]:
            print(f"      - {f.split('/')[-1]}")
        if len(wordlist_selection.username_files) > 5:
            print(f"      ... and {len(wordlist_selection.username_files) - 5} more")

        print(f"\n    Password wordlists:")
        for f in wordlist_selection.password_files[:5]:
            print(f"      - {f.split('/')[-1]}")
        if len(wordlist_selection.password_files) > 5:
            print(f"      ... and {len(wordlist_selection.password_files) - 5} more")

    else:
        # Fallback: try to get wordlists based on detected technologies
        tech_names = [t.name for t in detected_technologies] if detected_technologies else ["generic"]
        username_files, password_files, reasoning = get_wordlists_for_technologies(tech_names)

        if username_files or password_files:
            print(f"    {reasoning}")
            usernames = load_multiple_wordlists(
                username_files,
                limit_per_file=MAX_USERNAMES_PER_FILE,
                total_limit=TOTAL_USERNAME_LIMIT,
            )
            passwords = load_multiple_wordlists(
                password_files,
                limit_per_file=MAX_PASSWORDS_PER_FILE,
                total_limit=TOTAL_PASSWORD_LIMIT,
            )
        else:
            # Ultimate fallback
            print("    Using default wordlists (SecLists not available)")
            usernames = DEFAULT_USERNAMES
            passwords = DEFAULT_PASSWORDS

    # Ensure we have at least some credentials to test
    if not usernames:
        usernames = DEFAULT_USERNAMES
        print("    [!] No usernames loaded, using defaults")
    if not passwords:
        passwords = DEFAULT_PASSWORDS
        print("    [!] No passwords loaded, using defaults")

    print(f"\n    Total unique usernames: {len(usernames)}")
    print(f"    Total unique passwords: {len(passwords)}")

    total_attempts = len(endpoints) * len(usernames) * len(passwords)
    print(f"    Max credential combinations: {total_attempts}")

    results = []

    for endpoint in endpoints:
        print(f"\n[*] Testing endpoint: {endpoint.url}")
        endpoint_results, found_valid = _test_endpoint(
            endpoint, base_url, usernames, passwords
        )
        results.extend(endpoint_results)

        if found_valid:
            print(f"[+] Valid credentials found! Stopping further tests on this endpoint.")

    return {
        "credential_results": results,
        "current_phase": "complete",
        "errors": errors,
    }


def _test_endpoint(
    endpoint: LoginEndpoint,
    base_url: str,
    usernames: list[str],
    passwords: list[str],
) -> tuple[list[CredentialTestResult], bool]:
    """Test an endpoint with username/password combinations using parallel threads.

    Args:
        endpoint: The login endpoint to test.
        base_url: Base URL of the target.
        usernames: List of usernames to try.
        passwords: List of passwords to try.

    Returns:
        Tuple of (results list, whether valid creds were found).
    """
    results = []
    found_valid = threading.Event()
    results_lock = threading.Lock()

    # Resolve the form action URL
    action_url = endpoint.url
    if action_url.startswith("/"):
        action_url = f"{base_url.rstrip('/')}{action_url}"
    elif not action_url.startswith(("http://", "https://")):
        action_url = f"{base_url.rstrip('/')}/{action_url}"

    # Identify username and password field names
    username_field, password_field = _identify_fields(endpoint.form_fields)

    print(f"    Form fields: {username_field}={{}}, {password_field}={{...}}")

    # Build credential combinations lazily to reduce memory usage
    combinations = itertools.product(usernames, passwords)
    total_combinations = len(usernames) * len(passwords)
    print(f"    Testing {total_combinations} combinations with adaptive threading...")

    # Thread-local HTTP clients
    thread_local = threading.local()
    clients: list[httpx.Client] = []
    clients_lock = threading.Lock()
    ssl_verify = get_ssl_verify()

    def get_client():
        """Get or create thread-local HTTP client."""
        if not hasattr(thread_local, 'client'):
            thread_local.client = httpx.Client(
                timeout=REQUEST_TIMEOUT,
                follow_redirects=False,
                verify=ssl_verify,
            )
            with clients_lock:
                clients.append(thread_local.client)
        return thread_local.client

    def test_credential(cred_tuple: tuple[str, str]) -> CredentialTestResult | None:
        """Test a single credential pair."""
        if found_valid.is_set():
            return None  # Skip if we already found valid creds

        username, password = cred_tuple
        client = get_client()

        # Small delay to avoid overwhelming the target
        time.sleep(REQUEST_DELAY)

        result = _try_login(
            client,
            endpoint,
            action_url,
            username,
            password,
            username_field,
            password_field,
        )

        if result.success:
            found_valid.set()  # Signal other threads to stop

        return result

    # Configure adaptive threading
    min_threads, max_threads = get_thread_config()
    config = ThreadConfig(
        min_threads=min_threads,
        max_threads=max_threads,
        scale_interval=SCALE_INTERVAL,
    )

    def progress_callback(done: int, total: int):
        """Print progress updates."""
        if done % 50 == 0 or done == total:
            print(f"    Tested {done}/{total} combinations...")

    # Run parallel credential testing
    with AdaptiveThreadPool(config) as pool:
        for result in pool.map_with_progress(
            test_credential,
            combinations,
            progress_callback,
            total_count=total_combinations,
        ):
            if result is not None:
                with results_lock:
                    results.append(result)

            # Stop early if valid creds found
            if found_valid.is_set():
                pool.stop()
                break

    with clients_lock:
        for client in clients:
            try:
                client.close()
            except Exception:
                pass

    return results, found_valid.is_set()


def _identify_fields(form_fields: list[str]) -> tuple[str, str]:
    """Identify username and password field names.

    Args:
        form_fields: List of form field names.

    Returns:
        Tuple of (username_field, password_field).
    """
    username_field = None
    password_field = None

    for field in form_fields:
        field_lower = field.lower()
        if any(kw in field_lower for kw in ["user", "email", "login", "name", "account"]):
            if not username_field:
                username_field = field
        elif any(kw in field_lower for kw in ["pass", "pwd", "secret"]):
            if not password_field:
                password_field = field

    # Fallbacks
    username_field = username_field or "username"
    password_field = password_field or "password"

    return username_field, password_field


def _try_login(
    client: httpx.Client,
    endpoint: LoginEndpoint,
    url: str,
    username: str,
    password: str,
    username_field: str,
    password_field: str,
) -> CredentialTestResult:
    """Attempt a single login.

    Args:
        client: HTTP client to use.
        endpoint: Login endpoint configuration.
        url: Full URL to submit to.
        username: Username to try.
        password: Password to try.
        username_field: Name of the username form field.
        password_field: Name of the password form field.

    Returns:
        CredentialTestResult with success/failure info.
    """
    # Build form data
    data = dict(endpoint.additional_fields)
    data[username_field] = username
    data[password_field] = password

    try:
        if endpoint.method.upper() == "POST":
            response = client.post(
                url,
                data=data,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
            )
        else:
            response = client.get(
                url,
                params=data,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
            )

        # Detect success/failure
        success, evidence = _detect_success(response, username)

        return CredentialTestResult(
            endpoint_url=url,
            username=username,
            password=password,
            success=success,
            response_code=response.status_code,
            evidence=evidence,
        )
    except httpx.TimeoutException:
        return CredentialTestResult(
            endpoint_url=url,
            username=username,
            password=password,
            success=False,
            response_code=0,
            evidence="Request timed out",
        )
    except httpx.RequestError as e:
        return CredentialTestResult(
            endpoint_url=url,
            username=username,
            password=password,
            success=False,
            response_code=0,
            evidence=f"Request failed: {str(e)}",
        )


def _detect_success(response: httpx.Response, username: str) -> tuple[bool, str]:
    """Heuristically detect if a login was successful.

    Args:
        response: HTTP response from login attempt.
        username: Username that was tried.

    Returns:
        Tuple of (success boolean, evidence string).
    """
    # Check for redirect to dashboard/home/success pages
    if response.status_code in (301, 302, 303, 307, 308):
        location = response.headers.get("location", "").lower()
        success_paths = ["dashboard", "home", "welcome", "account", "profile", "admin", "panel"]
        if any(path in location for path in success_paths):
            return True, f"Redirect to success page: {location}"

        # Also check it's not redirecting back to login
        failure_paths = ["login", "signin", "auth", "error", "failed"]
        if any(path in location for path in failure_paths):
            return False, f"Redirect back to login: {location}"

    # Check response body for indicators
    body = response.text.lower()

    # Failure indicators (check first - more common)
    failure_indicators = [
        "invalid",
        "incorrect",
        "wrong",
        "failed",
        "error",
        "denied",
        "unauthorized",
        "bad credentials",
        "login failed",
        "authentication failed",
        "invalid username",
        "invalid password",
    ]
    for indicator in failure_indicators:
        if indicator in body:
            return False, f"Failure indicator: '{indicator}'"

    # Success indicators
    success_indicators = [
        "welcome",
        "dashboard",
        "logout",
        "sign out",
        "my account",
        "logged in",
        f"hello {username.lower()}",
        f"welcome {username.lower()}",
    ]
    for indicator in success_indicators:
        if indicator in body:
            return True, f"Success indicator: '{indicator}'"

    # Check for session cookie being set
    set_cookie = response.headers.get("set-cookie", "").lower()
    if set_cookie:
        session_indicators = ["session", "auth", "token", "logged", "jwt", "sid"]
        for indicator in session_indicators:
            if indicator in set_cookie:
                return True, f"Session cookie set: contains '{indicator}'"

    # 200 response without clear failure is ambiguous
    if response.status_code == 200 and "login" not in response.url.path.lower():
        return False, "Ambiguous: 200 response but no clear success indicators"

    return False, "No success indicators found"
