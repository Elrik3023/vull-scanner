"""Port scanner node to check HTTP/HTTPS availability."""

import socket
from vull_scanner.state import ScannerState, PortScanResult


def port_scanner_node(state: ScannerState) -> dict:
    """Scan ports 80 and 443 to determine available protocols.

    Args:
        state: Current scanner state with target hostname.

    Returns:
        Updated state with port scan results.
    """
    hostname = state["target_url"]
    timeout = 5.0  # Socket timeout in seconds

    print(f"[*] Scanning ports on {hostname}...")

    port_80_open = _check_port(hostname, 80, timeout)
    port_443_open = _check_port(hostname, 443, timeout)

    print(f"    Port 80 (HTTP):  {'OPEN' if port_80_open else 'CLOSED'}")
    print(f"    Port 443 (HTTPS): {'OPEN' if port_443_open else 'CLOSED'}")

    # Determine preferred protocol (prefer HTTPS)
    if port_443_open:
        preferred_protocol = "https"
        base_url = f"https://{hostname}"
    elif port_80_open:
        preferred_protocol = "http"
        base_url = f"http://{hostname}"
    else:
        preferred_protocol = None
        base_url = None

    result = PortScanResult(
        port_80_open=port_80_open,
        port_443_open=port_443_open,
        preferred_protocol=preferred_protocol,
        base_url=base_url,
    )

    errors = []
    next_phase = "login_discovery"

    if not port_80_open and not port_443_open:
        errors.append(f"Neither port 80 nor 443 is open on {hostname}")
        next_phase = "complete"
    else:
        print(f"[*] Using {preferred_protocol.upper()} ({base_url})")

    return {
        "port_scan": result,
        "current_phase": next_phase,
        "errors": errors,
    }


def _check_port(hostname: str, port: int, timeout: float) -> bool:
    """Check if a port is open on the target host.

    Args:
        hostname: Target hostname.
        port: Port number to check.
        timeout: Connection timeout in seconds.

    Returns:
        True if port is open, False otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((hostname, port))
        sock.close()
        return result == 0
    except socket.error:
        return False
