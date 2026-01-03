"""HTTP tools for LLM-driven web crawling."""

from langchain_core.tools import tool
import httpx


@tool
def fetch_page(url: str) -> str:
    """Fetch a web page and return its HTML content.

    Use this to retrieve the HTML of any page on the target website.
    Useful for finding login forms, links, and other content.

    Args:
        url: The full URL to fetch (e.g., https://example.com/login)

    Returns:
        The HTTP status code and HTML content (truncated to 15000 chars),
        or an error message if the request fails.
    """
    try:
        with httpx.Client(
            timeout=10.0,
            follow_redirects=True,
            verify=False,  # Allow self-signed certs
        ) as client:
            response = client.get(url, headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"})
            content = response.text[:15000]  # Truncate large pages
            return f"Status: {response.status_code}\nFinal URL: {response.url}\n\nContent:\n{content}"
    except httpx.TimeoutException:
        return f"Error: Request to {url} timed out"
    except httpx.RequestError as e:
        return f"Error fetching {url}: {str(e)}"


@tool
def fetch_robots_txt(base_url: str) -> str:
    """Fetch the robots.txt file from a website to discover hidden paths.

    Robots.txt often reveals admin panels, login pages, and other
    interesting endpoints that the site owner wants to hide from crawlers.

    Args:
        base_url: The base URL of the website (e.g., https://example.com)

    Returns:
        The content of robots.txt, or a message if not found.
    """
    url = f"{base_url.rstrip('/')}/robots.txt"
    try:
        with httpx.Client(
            timeout=10.0,
            verify=False,
        ) as client:
            response = client.get(url, headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"})
            if response.status_code == 200:
                return f"robots.txt found:\n\n{response.text}"
            return f"robots.txt not found (HTTP {response.status_code})"
    except httpx.TimeoutException:
        return "Error: Request to robots.txt timed out"
    except httpx.RequestError as e:
        return f"Error fetching robots.txt: {str(e)}"
