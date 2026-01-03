"""Input node for URL validation and normalization."""

from vull_scanner.state import ScannerState
from vull_scanner.utils.validation import validate_target, ValidationError
from vull_scanner.utils.logging import get_logger

logger = get_logger("input_node")


def input_node(state: ScannerState) -> dict:
    """Validate and normalize the input URL.

    Validates the target against SSRF protections and normalizes it
    for port scanning.

    Args:
        state: Current scanner state with target_url and allow_private flag.

    Returns:
        Updated state fields.

    Raises:
        ValidationError: If target validation fails.
    """
    target_url = state["target_url"]
    allow_private = state.get("allow_private", False)

    # Validate and sanitize the target using SSRF protection
    try:
        hostname = validate_target(target_url, allow_private=allow_private)
    except ValidationError as e:
        logger.error(f"Target validation failed: {e}")
        raise

    logger.info(f"Target hostname: {hostname}")

    return {
        "target_url": hostname,
        "current_phase": "port_scan",
        "login_endpoints": [],
        "detected_technologies": [],
        "wordlist_selection": None,
        "nmap_result": None,
        "ffuf_result": None,
        "amass_result": None,
        "discovered_subdomains": [],
        "credential_results": [],
        "errors": [],
    }
