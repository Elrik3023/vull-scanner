"""HTML parsing tools for LLM-driven login discovery."""

from langchain_core.tools import tool
from bs4 import BeautifulSoup
import json


@tool
def extract_links(html_content: str, base_url: str) -> str:
    """Extract all links from HTML content.

    Use this after fetching a page to find all links that might lead
    to login pages or other interesting endpoints.

    Args:
        html_content: The HTML content to parse (from fetch_page)
        base_url: The base URL for resolving relative links

    Returns:
        JSON list of discovered links with their text labels.
    """
    # Handle the fetch_page output format
    if html_content.startswith("Status:"):
        lines = html_content.split("\n")
        content_start = html_content.find("Content:\n")
        if content_start != -1:
            html_content = html_content[content_start + 9:]

    soup = BeautifulSoup(html_content, "lxml")
    links = []
    seen_urls = set()

    for a in soup.find_all("a", href=True):
        href = a["href"]
        text = a.get_text(strip=True)[:50]

        # Skip empty, javascript, and anchor links
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        # Resolve relative URLs
        if href.startswith("/"):
            href = f"{base_url.rstrip('/')}{href}"
        elif not href.startswith(("http://", "https://")):
            href = f"{base_url.rstrip('/')}/{href}"

        # Deduplicate
        if href not in seen_urls:
            seen_urls.add(href)
            links.append({"url": href, "text": text or "(no text)"})

    # Sort by relevance - login-related links first
    def relevance(link):
        url_lower = link["url"].lower()
        text_lower = link["text"].lower()
        keywords = ["login", "signin", "sign-in", "auth", "admin", "account", "user"]
        for kw in keywords:
            if kw in url_lower or kw in text_lower:
                return 0
        return 1

    links.sort(key=relevance)

    return json.dumps(links[:50], indent=2)


@tool
def extract_forms(html_content: str) -> str:
    """Extract all forms from HTML content.

    Use this to find login forms and other input forms on a page.
    Look for forms with password fields - those are likely login forms.

    Args:
        html_content: The HTML content to parse (from fetch_page)

    Returns:
        JSON list of forms with action, method, and input fields.
    """
    # Handle the fetch_page output format
    if html_content.startswith("Status:"):
        content_start = html_content.find("Content:\n")
        if content_start != -1:
            html_content = html_content[content_start + 9:]

    soup = BeautifulSoup(html_content, "lxml")
    forms = []

    for form in soup.find_all("form"):
        form_data = {
            "action": form.get("action", ""),
            "method": form.get("method", "GET").upper(),
            "id": form.get("id", ""),
            "inputs": [],
        }

        for inp in form.find_all(["input", "button"]):
            input_data = {
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "id": inp.get("id", ""),
                "placeholder": inp.get("placeholder", ""),
            }
            # Only include if it has a name (submittable)
            if input_data["name"] or input_data["type"] == "submit":
                form_data["inputs"].append(input_data)

        # Check if this looks like a login form
        has_password = any(i["type"] == "password" for i in form_data["inputs"])
        has_text_input = any(i["type"] in ("text", "email") for i in form_data["inputs"])
        form_data["likely_login_form"] = has_password and has_text_input

        forms.append(form_data)

    return json.dumps(forms, indent=2)


@tool
def analyze_form(form_action: str, form_method: str, form_inputs_json: str, page_url: str) -> str:
    """Analyze a form to determine if it's a login form and extract field details.

    Call this for each form that looks like it might be a login form.
    It will return structured information about the form fields.

    Args:
        form_action: The form's action URL (from extract_forms)
        form_method: The HTTP method - GET or POST (from extract_forms)
        form_inputs_json: JSON string of form inputs (from extract_forms)
        page_url: The URL of the page containing the form

    Returns:
        JSON analysis with field names and login form classification.
    """
    try:
        inputs = json.loads(form_inputs_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON for form inputs"})

    # Categorize fields
    password_fields = [i for i in inputs if i.get("type") == "password"]
    text_fields = [i for i in inputs if i.get("type") in ("text", "email")]
    hidden_fields = [i for i in inputs if i.get("type") == "hidden"]
    submit_fields = [i for i in inputs if i.get("type") == "submit"]

    # Determine if this is a login form
    is_login_form = len(password_fields) >= 1 and len(text_fields) >= 1

    # Find the likely username/email field
    username_field = None
    for field in text_fields:
        name_lower = field.get("name", "").lower()
        placeholder_lower = field.get("placeholder", "").lower()
        if any(kw in name_lower or kw in placeholder_lower for kw in ["user", "email", "login", "name"]):
            username_field = field.get("name")
            break
    if not username_field and text_fields:
        username_field = text_fields[0].get("name")

    # Find the password field
    password_field = password_fields[0].get("name") if password_fields else None

    # Resolve the form action URL
    action_url = form_action
    if not action_url:
        action_url = page_url
    elif action_url.startswith("/"):
        # Parse the base from page_url
        from urllib.parse import urlparse

        parsed = urlparse(page_url)
        action_url = f"{parsed.scheme}://{parsed.netloc}{action_url}"
    elif not action_url.startswith(("http://", "https://")):
        action_url = f"{page_url.rstrip('/')}/{action_url}"

    result = {
        "is_login_form": is_login_form,
        "action_url": action_url,
        "method": form_method,
        "username_field": username_field,
        "password_field": password_field,
        "hidden_fields": {f.get("name"): "" for f in hidden_fields if f.get("name")},
        "all_field_names": [i.get("name") for i in inputs if i.get("name")],
    }

    return json.dumps(result, indent=2)
