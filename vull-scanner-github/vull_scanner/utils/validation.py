"""Input validation and SSRF prevention for the vulnerability scanner."""

import re
import ipaddress
from urllib.parse import urlparse


class ValidationError(Exception):
    """Raised when input validation fails."""

    pass


# Hosts that should always be blocked
BLOCKED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    # Cloud metadata endpoints
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "100.100.100.200",  # Alibaba Cloud
}

# Private/reserved IP networks
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]

# Valid URL schemes
ALLOWED_SCHEMES = {"http", "https"}

# Hostname pattern
HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$")


def validate_target(target: str, allow_private: bool = False) -> str:
    """Validate and sanitize scan target.

    Args:
        target: URL or hostname to validate.
        allow_private: Allow private/internal IP ranges.

    Returns:
        Validated and normalized hostname.

    Raises:
        ValidationError: If target is invalid or blocked.
    """
    if not target or not target.strip():
        raise ValidationError("Target cannot be empty")

    target = target.strip()

    # Normalize URL - add scheme if missing
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    try:
        parsed = urlparse(target)
    except Exception as e:
        raise ValidationError(f"Invalid URL format: {e}")

    # Validate scheme
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValidationError(
            f"Invalid scheme: {parsed.scheme}. Only http and https are allowed."
        )

    # Extract hostname (remove port if present)
    hostname = parsed.netloc.split(":")[0].lower()

    if not hostname:
        raise ValidationError("Empty hostname")

    # Check blocked hosts
    if hostname in BLOCKED_HOSTS:
        raise ValidationError(f"Target not allowed: {hostname}")

    # Check for IP addresses
    try:
        ip = ipaddress.ip_address(hostname)

        # Block private IPs unless explicitly allowed
        if not allow_private:
            # Check if it's a private IP
            if ip.is_private:
                raise ValidationError(
                    f"Private IP not allowed: {hostname}. "
                    "Use --allow-private to scan internal networks."
                )

            # Check reserved ranges
            if ip.is_reserved or ip.is_loopback or ip.is_link_local:
                raise ValidationError(f"Reserved IP not allowed: {hostname}")

            # Check against private network ranges
            for network in PRIVATE_NETWORKS:
                if ip in network:
                    raise ValidationError(
                        f"Private IP not allowed: {hostname}. "
                        "Use --allow-private to scan internal networks."
                    )

    except ValueError:
        # Not an IP address, validate as hostname
        if not HOSTNAME_PATTERN.match(hostname):
            raise ValidationError(f"Invalid hostname format: {hostname}")

        # Check for suspicious patterns
        if ".." in hostname:
            raise ValidationError(f"Invalid hostname: {hostname}")

    return hostname


def validate_port(port: int | str) -> int:
    """Validate a port number.

    Args:
        port: Port number to validate.

    Returns:
        Validated port as integer.

    Raises:
        ValidationError: If port is invalid.
    """
    try:
        port_int = int(port)
    except (ValueError, TypeError):
        raise ValidationError(f"Invalid port: {port}")

    if not 1 <= port_int <= 65535:
        raise ValidationError(f"Port out of range: {port_int}")

    return port_int


def sanitize_path(path: str) -> str:
    """Sanitize a file path to prevent path traversal.

    Args:
        path: Path to sanitize.

    Returns:
        Sanitized path.

    Raises:
        ValidationError: If path contains traversal attempts.
    """
    if not path:
        return path

    # Check for path traversal
    if ".." in path or path.startswith("/"):
        raise ValidationError(f"Path traversal detected: {path}")

    # Check for null bytes
    if "\x00" in path:
        raise ValidationError("Null byte in path")

    return path


def is_valid_url(url: str) -> bool:
    """Check if a string is a valid URL.

    Args:
        url: String to check.

    Returns:
        True if valid URL, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False
