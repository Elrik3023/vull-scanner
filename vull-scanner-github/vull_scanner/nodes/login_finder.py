"""Login finder node using LLM with tools (ReAct pattern)."""

import json
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from vull_scanner.state import ScannerState, LoginEndpoint, DetectedTechnology, WordlistSelection
from vull_scanner.tools import TOOLS
from vull_scanner.utils.seclists import get_wordlists_for_technologies, list_available_categories
from vull_scanner.utils.thread_manager import parallel_execute
from vull_scanner.utils.logging import get_logger
import httpx
import threading
from bs4 import BeautifulSoup
from urllib.parse import urljoin

logger = get_logger("login_finder")


SYSTEM_PROMPT = """You are an expert security researcher with access to professional penetration testing tools.
Your mission is to thoroughly scan a target website to find ALL login endpoints and identify the technology stack.

## Your Goals
1. Discover ALL login endpoints on the target website (including hidden ones)
2. Identify the technology stack (CMS, frameworks, server software)
3. Find subdomains that might have additional login pages
4. Use professional tools (nmap, ffuf, amass) for thorough reconnaissance

## CRITICAL: You MUST Always Do These Steps (Even Without External Tools)

### MANDATORY Phase 1: Basic Web Crawling (ALWAYS DO THIS FIRST!)
1. fetch_page(base_url) - Get the homepage and look for login forms
2. extract_forms(html_content) - Extract ALL forms from the homepage
3. For each form, use analyze_form() to check if it's a login form
4. fetch_robots_txt(base_url) - Check for hidden paths
5. extract_links(html_content, base_url) - Get all links and check for login-related ones
6. Check these COMMON LOGIN PATHS by fetching them directly:
   - /login, /signin, /auth, /admin, /user/login, /account/login
   - /wp-login.php, /wp-admin (WordPress)
   - /administrator (Joomla)
   - /user/login (Drupal)
   - /login.jsp, /login.aspx, /login.php, /login.html

### Phase 2: External Tools (If Available)
1. Call check_available_scanners() to see what tools are available
2. If ffuf is available, run ffuf_login_discovery(base_url) to find hidden login pages
3. If nmap is available, run nmap_scan(target, "service") for detailed port/service info
4. If amass is available, run amass_subdomain_enum(domain) to find subdomains

### Phase 3: Deep Analysis
1. For each discovered page that might have a login form, fetch it
2. Extract forms and analyze them for login functionality
3. Pay special attention to pages found by ffuf

## Tools Available

### External Security Scanners (POWERFUL - USE THESE!)
- check_available_scanners(): Check which tools are installed (call this first!)
- nmap_scan(target, scan_type, ports): Network scan for ports and services
  - scan_type: "quick", "service" (recommended), "aggressive", or "vuln"
- ffuf_directory_scan(base_url, extensions): Find hidden directories and files
- ffuf_login_discovery(base_url): Specifically find login/auth pages
- ffuf_api_discovery(base_url): Find API endpoints
- amass_subdomain_enum(domain, passive_only): Discover subdomains

### Web Crawling Tools
- fetch_page(url): Get HTML content of any page
- fetch_robots_txt(base_url): Check robots.txt for hidden paths
- extract_links(html_content, base_url): Get all links from a page
- extract_forms(html_content): Get all forms from a page
- analyze_form(action, method, inputs_json, page_url): Analyze if a form is a login form

## Technology Detection Hints
- WordPress: wp-content, wp-includes, /wp-admin, WordPress in meta generator
- Joomla: /administrator, Joomla in meta, /components/com_
- Drupal: /sites/default, Drupal.settings, drupal.js
- Tomcat: /manager, tomcat in headers, .jsp files
- phpMyAdmin: /phpmyadmin, pma in URLs
- PHP: .php extensions, PHP in headers
- ASP.NET: .aspx, __VIEWSTATE, ASP.NET in headers
- Laravel: laravel_session cookie, /public
- Django: csrfmiddlewaretoken, django in cookies
- Router/Network devices: firmware, config, system info pages

## Important Guidelines
- ALWAYS fetch the homepage first and analyze all forms - this is MANDATORY
- ALWAYS check common login paths (/login, /admin, /signin, etc.) by fetching them directly
- Use ffuf_login_discovery if available - it's specifically designed to find login pages
- If amass finds interesting subdomains, note them for the final report
- If nmap finds additional ports (8080, 8443, etc.), scan those too
- When you find a form, ALWAYS use analyze_form() to check if it's a login form
- After all scanning is complete, you MUST provide a FINAL SUMMARY with the JSON format below
- DO NOT stop until you have checked the homepage AND common login paths

## Final Summary Format
When done, output exactly this JSON format:
```json
{
  "detected_technologies": [
    {
      "name": "wordpress",
      "confidence": "high",
      "evidence": "Found wp-content directory and WordPress meta generator tag"
    }
  ],
  "login_endpoints_found": [
    {
      "url": "https://example.com/wp-login.php",
      "method": "POST",
      "username_field": "log",
      "password_field": "pwd",
      "additional_fields": {}
    }
  ],
  "subdomains_found": ["admin.example.com", "dev.example.com"],
  "additional_ports": [8080, 8443],
  "interesting_paths": ["/backup", "/admin-panel", "/api"]
}
```

Available technology categories for wordlist selection: """ + ", ".join(list_available_categories())


def create_model():
    """Create the OpenAI model with tools bound."""
    model = ChatOpenAI(
        model="gpt-4o",
        temperature=0,
        max_tokens=4096,
    )
    return model.bind_tools(TOOLS)


# Common login paths to check as fallback
COMMON_LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/admin", "/administrator", "/admin/login", "/user/login",
    "/account/login", "/members/login", "/portal", "/portal/login",
    "/wp-login.php", "/wp-admin",  # WordPress
    "/administrator/index.php",  # Joomla
    "/user/login", "/user",  # Drupal
    "/login.jsp", "/login.aspx", "/login.php", "/login.html",
    "/doLogin", "/j_security_check",  # Java/J2EE
    "/Account/Login", "/Account/SignIn",  # ASP.NET MVC
    "/bank/login.aspx", "/bank/login.jsp",  # Banking apps
]


def _check_common_login_paths(base_url: str) -> list[LoginEndpoint]:
    """Fallback: directly check common login paths for forms using parallel requests.

    Args:
        base_url: Base URL to check.

    Returns:
        List of discovered LoginEndpoints.
    """
    endpoints = []
    endpoints_lock = threading.Lock()
    seen_urls = set()
    seen_lock = threading.Lock()

    # Build URL list
    urls_to_check = list(set([base_url] + [urljoin(base_url, path) for path in COMMON_LOGIN_PATHS]))

    # Thread-local HTTP clients
    thread_local = threading.local()

    def get_client():
        if not hasattr(thread_local, 'client'):
            thread_local.client = httpx.Client(
                timeout=10.0,
                follow_redirects=True,
                verify=False,
            )
        return thread_local.client

    def check_url(url: str) -> list[LoginEndpoint]:
        """Check a single URL for login forms."""
        local_endpoints = []

        try:
            client = get_client()
            response = client.get(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
            )

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                forms = soup.find_all("form")

                for form in forms:
                    # Check if this form looks like a login form
                    inputs = form.find_all("input")
                    input_types = [inp.get("type", "text").lower() for inp in inputs]
                    input_names = [inp.get("name", "").lower() for inp in inputs]

                    has_password = "password" in input_types
                    has_text_or_email = "text" in input_types or "email" in input_types
                    has_login_field = any(
                        name in ["username", "user", "login", "email", "uid", "userid", "user_id", "uname"]
                        for name in input_names
                    )

                    if has_password and (has_text_or_email or has_login_field):
                        # Found a login form
                        action = form.get("action", "")
                        method = form.get("method", "POST").upper()

                        if action:
                            action_url = urljoin(str(response.url), action)
                        else:
                            action_url = str(response.url)

                        # Get field names
                        field_names = [inp.get("name") for inp in inputs if inp.get("name")]

                        # Check for CSRF field
                        csrf_field = None
                        hidden_fields = {}
                        for inp in inputs:
                            if inp.get("type", "").lower() == "hidden":
                                name = inp.get("name", "")
                                value = inp.get("value", "")
                                if name:
                                    hidden_fields[name] = value
                                    if "csrf" in name.lower() or "token" in name.lower():
                                        csrf_field = name

                        # Check if we've seen this action URL
                        with seen_lock:
                            if action_url in seen_urls:
                                continue
                            seen_urls.add(action_url)

                        local_endpoints.append(LoginEndpoint(
                            url=action_url,
                            method=method,
                            form_fields=field_names,
                            csrf_field=csrf_field,
                            additional_fields=hidden_fields,
                        ))
                        print(f"    [+] Fallback found login form at: {action_url}")

        except Exception as e:
            logger.debug(f"Error checking URL {url}: {e}")

        return local_endpoints

    print(f"    Checking {len(urls_to_check)} URLs in parallel...")

    # Run parallel URL checks
    results = parallel_execute(check_url, urls_to_check, max_threads=10, progress_interval=5)

    # Collect all endpoints
    for result in results:
        if result:
            endpoints.extend(result)

    return endpoints


def login_finder_node(state: ScannerState) -> dict:
    """LLM node for discovering login endpoints and detecting technologies.

    Uses GPT-4o with tools in a ReAct pattern to crawl the site,
    find login forms, and identify the technology stack.

    Args:
        state: Current scanner state.

    Returns:
        Updated state with new messages.
    """
    model = create_model()

    # Build initial message if this is the first call
    messages = list(state.get("messages", []))
    initial_messages = []

    if not messages:
        base_url = state["port_scan"].base_url
        print(f"\n[*] Starting login endpoint discovery on {base_url}...")
        print("[*] Also detecting technology stack for wordlist selection...")
        initial_messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=f"Find all login endpoints and detect the technology stack on: {base_url}"),
        ]
        messages = initial_messages

    # Invoke the model
    response = model.invoke(messages)

    # Return initial messages (if first call) plus the response
    # The add_messages reducer will append these to the state
    if initial_messages:
        return {"messages": initial_messages + [response]}
    return {"messages": [response]}


def should_continue(state: ScannerState) -> str:
    """Determine if we should continue tool calls or parse results.

    Args:
        state: Current scanner state.

    Returns:
        "tools" to process tool calls, "parse_results" when done.
    """
    messages = state.get("messages", [])
    if not messages:
        return "tools"

    last_message = messages[-1]

    # If the last message has tool calls, continue to process them
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        return "tools"

    # Otherwise, the LLM is done - parse results
    return "parse_results"


def parse_login_results_node(state: ScannerState) -> dict:
    """Parse the LLM's findings into structured objects.

    Extracts login endpoints, detected technologies, subdomains, and other findings
    from the LLM conversation, then selects appropriate wordlists.

    Args:
        state: Scanner state with completed LLM conversation.

    Returns:
        Updated state with login_endpoints, detected_technologies, wordlist_selection, and more.
    """
    messages = state.get("messages", [])
    login_endpoints = []
    detected_technologies = []
    discovered_subdomains = []
    additional_ports = []
    interesting_paths = []
    errors = list(state.get("errors", []))

    # Find the final AI message with the summary
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.content:
            content = msg.content if isinstance(msg.content, str) else str(msg.content)

            # Try to extract JSON from the message
            try:
                # Look for JSON block in the response
                json_start = content.find("{")
                json_end = content.rfind("}") + 1

                if json_start != -1 and json_end > json_start:
                    json_str = content[json_start:json_end]
                    data = json.loads(json_str)

                    # Extract detected technologies
                    if "detected_technologies" in data:
                        for tech in data["detected_technologies"]:
                            detected_tech = DetectedTechnology(
                                name=tech.get("name", "unknown"),
                                confidence=tech.get("confidence", "low"),
                                evidence=tech.get("evidence", ""),
                            )
                            detected_technologies.append(detected_tech)

                    # Extract login endpoints
                    if "login_endpoints_found" in data:
                        for ep in data["login_endpoints_found"]:
                            endpoint = LoginEndpoint(
                                url=ep.get("url", ""),
                                method=ep.get("method", "POST"),
                                form_fields=[
                                    ep.get("username_field", "username"),
                                    ep.get("password_field", "password"),
                                ],
                                csrf_field=list(ep.get("additional_fields", {}).keys())[0]
                                if ep.get("additional_fields")
                                else None,
                                additional_fields=ep.get("additional_fields", {}),
                            )
                            if endpoint.url:
                                login_endpoints.append(endpoint)

                    # Extract subdomains found by amass
                    if "subdomains_found" in data:
                        discovered_subdomains = data["subdomains_found"]

                    # Extract additional ports found by nmap
                    if "additional_ports" in data:
                        additional_ports = data["additional_ports"]

                    # Extract interesting paths found by ffuf
                    if "interesting_paths" in data:
                        interesting_paths = data["interesting_paths"]

                    break
            except (json.JSONDecodeError, KeyError, IndexError) as e:
                logger.debug(f"Failed to parse JSON from LLM response: {e}")
                errors.append(f"Failed to parse LLM summary JSON: {e}")

    # If no structured output, try to extract from tool call results
    # Scan ALL messages for analyze_form results
    for msg in messages:
        if hasattr(msg, "content"):
            content = msg.content if isinstance(msg.content, str) else str(msg.content)

            # Look for analyze_form results with is_login_form: true
            if '"is_login_form": true' in content.lower() or '"is_login_form":true' in content.lower():
                try:
                    # Try to find JSON in the content
                    json_start = content.find("{")
                    json_end = content.rfind("}") + 1
                    if json_start != -1 and json_end > json_start:
                        json_str = content[json_start:json_end]
                        data = json.loads(json_str)
                        if data.get("is_login_form"):
                            # Get the action URL, fallback to page_url if action is relative
                            action_url = data.get("action_url", "")
                            page_url = data.get("page_url", "")

                            # If action URL is empty or relative, use page URL as base
                            if not action_url or action_url.startswith("/"):
                                if page_url:
                                    action_url = urljoin(page_url, action_url) if action_url else page_url

                            # Extract field names
                            field_names = data.get("all_field_names", [])
                            if not field_names:
                                # Try to get from username/password fields
                                username_field = data.get("username_field", "username")
                                password_field = data.get("password_field", "password")
                                field_names = [username_field, password_field]

                            endpoint = LoginEndpoint(
                                url=action_url,
                                method=data.get("method", "POST"),
                                form_fields=field_names,
                                csrf_field=list(data.get("hidden_fields", {}).keys())[0]
                                if data.get("hidden_fields")
                                else None,
                                additional_fields=data.get("hidden_fields", {}),
                            )
                            if endpoint.url and endpoint.url not in [e.url for e in login_endpoints]:
                                login_endpoints.append(endpoint)
                                print(f"    [+] Found login form via analyze_form: {endpoint.url}")
                except (json.JSONDecodeError, KeyError, IndexError) as e:
                    logger.debug(f"Failed to parse analyze_form result: {e}")

    # Print discovered subdomains
    if discovered_subdomains:
        print(f"\n[+] Discovered {len(discovered_subdomains)} subdomain(s):")
        for sub in discovered_subdomains[:10]:
            print(f"    - {sub}")
        if len(discovered_subdomains) > 10:
            print(f"    ... and {len(discovered_subdomains) - 10} more")

    # Print additional ports
    if additional_ports:
        print(f"\n[+] Additional ports found: {', '.join(map(str, additional_ports))}")

    # Print interesting paths
    if interesting_paths:
        print(f"\n[+] Interesting paths discovered:")
        for path in interesting_paths[:10]:
            print(f"    - {path}")

    # Print detected technologies
    if detected_technologies:
        print(f"\n[+] Detected {len(detected_technologies)} technology/technologies:")
        for tech in detected_technologies:
            print(f"    - {tech.name} ({tech.confidence} confidence): {tech.evidence[:60]}...")
    else:
        print("\n[!] No specific technologies detected, using generic wordlists")

    # Select wordlists based on detected technologies
    tech_names = [t.name for t in detected_technologies] if detected_technologies else ["generic"]
    username_files, password_files, reasoning = get_wordlists_for_technologies(tech_names)

    wordlist_selection = None
    if username_files or password_files:
        wordlist_selection = WordlistSelection(
            username_files=username_files,
            password_files=password_files,
            reasoning=reasoning,
        )
        print(f"\n[*] Wordlist selection: {reasoning}")
        print(f"    Username files: {len(username_files)}")
        print(f"    Password files: {len(password_files)}")

    # FALLBACK: If no login endpoints found, directly check common paths
    if not login_endpoints:
        print("\n[*] Running fallback: checking common login paths directly...")
        base_url = state["port_scan"].base_url
        fallback_endpoints = _check_common_login_paths(base_url)
        if fallback_endpoints:
            login_endpoints.extend(fallback_endpoints)
            print(f"    [+] Fallback found {len(fallback_endpoints)} login endpoint(s)")

    # Print login endpoints
    if login_endpoints:
        print(f"\n[+] Found {len(login_endpoints)} login endpoint(s):")
        for ep in login_endpoints:
            print(f"    - {ep.url}")
    else:
        print("\n[!] No login endpoints discovered")
        errors.append("No login endpoints found during discovery")

    next_phase = "credential_test" if login_endpoints else "complete"

    return {
        "login_endpoints": login_endpoints,
        "detected_technologies": detected_technologies,
        "wordlist_selection": wordlist_selection,
        "discovered_subdomains": discovered_subdomains,
        "current_phase": next_phase,
        "errors": errors,
    }
