"""State schema for the vulnerability scanner graph."""

from typing import Annotated, TypedDict
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage
from pydantic import BaseModel


class PortScanResult(BaseModel):
    """Result of port scanning."""

    port_80_open: bool = False
    port_443_open: bool = False
    preferred_protocol: str | None = None  # "http" or "https"
    base_url: str | None = None


class PortInfo(BaseModel):
    """Information about an open port from nmap scan."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    version: str = ""
    product: str = ""


class LoginEndpoint(BaseModel):
    """Discovered login endpoint."""

    url: str
    method: str = "POST"  # "GET" or "POST"
    form_fields: list[str] = []  # Field names like ["username", "password"]
    username_field: str | None = None
    password_field: str | None = None
    form_action: str | None = None  # Form submission URL
    csrf_field: str | None = None
    additional_fields: dict[str, str] = {}


class CredentialTestResult(BaseModel):
    """Result of a credential test."""

    endpoint_url: str
    username: str
    password: str
    success: bool
    response_code: int
    evidence: str  # Why we think it succeeded/failed


class DetectedTechnology(BaseModel):
    """Detected technology/framework on the target."""

    name: str  # e.g., "wordpress", "joomla", "drupal", "php", "asp.net"
    confidence: str  # "high", "medium", "low"
    evidence: str  # What indicated this technology
    version: str | None = None  # Version if detected


class WordlistSelection(BaseModel):
    """Selected wordlists for credential testing."""

    username_files: list[str]  # Paths to username wordlists
    password_files: list[str]  # Paths to password wordlists
    reasoning: str  # Why these wordlists were selected


class NmapResult(BaseModel):
    """Results from nmap scan."""

    target: str = ""
    open_ports: list[PortInfo] = []
    os_detection: str | None = None
    scripts_output: dict[str, str] = {}  # script_id -> output
    raw_output: str = ""
    scan_time: float = 0.0


class FFUFResult(BaseModel):
    """Single result from ffuf fuzzing."""

    url: str
    status_code: int
    content_length: int = 0
    content_words: int = 0
    content_lines: int = 0
    redirect_location: str = ""


class FFUFScanResult(BaseModel):
    """Results from a single ffuf scan with one wordlist."""

    base_url: str
    wordlist_used: str
    results: list[FFUFResult] = []
    total_requests: int = 0
    scan_time: float = 0.0


class FfufResult(BaseModel):
    """Legacy results from ffuf directory/file discovery."""

    discovered_paths: list[dict] = []  # List of {url, status, length}
    total_found: int = 0


class AmassResult(BaseModel):
    """Results from amass subdomain enumeration."""

    subdomains: list[str] = []
    interesting_subdomains: list[str] = []  # Subdomains with admin, dev, test, etc.
    total_found: int = 0


class SqlInjection(BaseModel):
    """Details of a SQL injection vulnerability."""

    parameter: str
    injection_type: str  # e.g., "boolean-based", "time-based", "UNION"
    payload: str = ""
    dbms: str = ""  # Database type detected


class SqlmapResult(BaseModel):
    """Results from sqlmap SQL injection testing."""

    target_url: str
    vulnerable: bool = False
    injections: list[SqlInjection] = []
    database_type: str = ""
    databases_found: list[str] = []
    tables_found: list[str] = []
    raw_output: str = ""


class CredentialResult(BaseModel):
    """Result of a single credential test (for burp_attacker)."""

    endpoint_url: str
    username: str
    password: str
    success: bool
    status_code: int
    response_length: int = 0
    evidence: str = ""


class BurpResult(BaseModel):
    """Results from credential brute-forcing attack."""

    endpoint_url: str
    attack_type: str = "ffuf_creds"
    total_attempts: int = 0
    successful_logins: list[CredentialResult] = []
    raw_output: str = ""


class ScannerState(TypedDict):
    """Main state schema for the vulnerability scanner."""

    # Input
    target_url: str
    allow_private: bool  # Allow scanning private/internal IPs
    show_passwords: bool  # Show passwords in output (default: masked)

    # Port scanning results
    port_scan: PortScanResult | None

    # Login discovery (LLM conversation)
    messages: Annotated[list[BaseMessage], add_messages]

    # Discovered login endpoints
    login_endpoints: list[LoginEndpoint]

    # Injectable endpoints (for SQLi testing)
    injectable_endpoints: list[str]

    # Technology detection
    detected_technologies: list[DetectedTechnology]

    # Dynamic wordlist selection
    wordlist_selection: WordlistSelection | None

    # External tool results
    nmap_result: NmapResult | None
    ffuf_result: FfufResult | None
    ffuf_results: list[FFUFScanResult]  # Multiple FFUF scan results
    amass_result: AmassResult | None
    discovered_subdomains: list[str]

    # SQL injection results
    sqlmap_results: list[SqlmapResult]

    # Credential brute-force results
    burp_results: list[BurpResult]

    # Credential testing results (original)
    credential_results: list[CredentialTestResult]

    # Error tracking
    errors: list[str]

    # Workflow control
    current_phase: str  # "init", "port_scan", "login_discovery", "credential_test", "complete"
