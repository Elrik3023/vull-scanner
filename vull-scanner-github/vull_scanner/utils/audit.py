"""Audit logging for security events and compliance."""

import json
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogger:
    """Immutable audit logger for security-relevant events.

    Logs are stored in JSON Lines format with checksums for integrity.
    """

    def __init__(self, log_dir: str | None = None):
        """Initialize audit logger.

        Args:
            log_dir: Directory for audit logs. Defaults to VULL_AUDIT_DIR
                    environment variable or '.vull_audit'.
        """
        if log_dir is None:
            log_dir = os.environ.get("VULL_AUDIT_DIR", ".vull_audit")

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        self.log_file = self.log_dir / f"audit_{self.session_id}.jsonl"

        # Track event sequence for integrity
        self._event_sequence = 0
        self._previous_hash = ""

    def _log(self, event_type: str, **details: Any) -> None:
        """Write an audit log entry.

        Args:
            event_type: Type of event (e.g., SCAN_STARTED, VULN_FOUND).
            **details: Event-specific details.
        """
        self._event_sequence += 1

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "sequence": self._event_sequence,
            "event_type": event_type,
            "previous_hash": self._previous_hash,
            **details,
        }

        # Calculate checksum for chain integrity
        entry_str = json.dumps(entry, sort_keys=True)
        entry["checksum"] = hashlib.sha256(entry_str.encode()).hexdigest()[:16]
        self._previous_hash = entry["checksum"]

        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def scan_started(self, target: str, user: str | None = None) -> None:
        """Log scan start event.

        Args:
            target: Scan target.
            user: Optional user identifier.
        """
        self._log(
            "SCAN_STARTED",
            target=target,
            user=user or os.environ.get("USER", "unknown"),
            pid=os.getpid(),
        )

    def scan_completed(
        self,
        target: str,
        duration: float,
        findings_count: int,
        success: bool = True,
    ) -> None:
        """Log scan completion event.

        Args:
            target: Scan target.
            duration: Scan duration in seconds.
            findings_count: Number of findings.
            success: Whether scan completed successfully.
        """
        self._log(
            "SCAN_COMPLETED",
            target=target,
            duration_seconds=duration,
            findings_count=findings_count,
            success=success,
        )

    def scan_failed(self, target: str, error: str) -> None:
        """Log scan failure event.

        Args:
            target: Scan target.
            error: Error message.
        """
        self._log("SCAN_FAILED", target=target, error=error)

    def vulnerability_found(
        self,
        vuln_type: str,
        endpoint: str,
        severity: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log vulnerability discovery.

        Args:
            vuln_type: Type of vulnerability (sqli, xss, etc.).
            endpoint: Affected endpoint.
            severity: Severity level (critical, high, medium, low, info).
            details: Additional details.
        """
        self._log(
            "VULNERABILITY_FOUND",
            vulnerability_type=vuln_type,
            endpoint=endpoint,
            severity=severity,
            details=details or {},
        )

    def credential_found(self, endpoint: str, username: str) -> None:
        """Log credential discovery.

        Note: Password is intentionally NOT logged for security.

        Args:
            endpoint: Login endpoint.
            username: Discovered username.
        """
        self._log(
            "CREDENTIAL_FOUND",
            endpoint=endpoint,
            username=username,
            # Password hash omitted - use separate secure storage
        )

    def tool_executed(
        self,
        tool_name: str,
        target: str,
        success: bool,
        duration: float | None = None,
    ) -> None:
        """Log external tool execution.

        Args:
            tool_name: Name of tool (nmap, ffuf, sqlmap, etc.).
            target: Tool target.
            success: Whether tool executed successfully.
            duration: Execution time in seconds.
        """
        self._log(
            "TOOL_EXECUTED",
            tool=tool_name,
            target=target,
            success=success,
            duration_seconds=duration,
        )

    def access_attempt(
        self,
        endpoint: str,
        method: str,
        success: bool,
        response_code: int | None = None,
    ) -> None:
        """Log access attempt to an endpoint.

        Args:
            endpoint: Target endpoint.
            method: HTTP method.
            success: Whether access was successful.
            response_code: HTTP response code.
        """
        self._log(
            "ACCESS_ATTEMPT",
            endpoint=endpoint,
            method=method,
            success=success,
            response_code=response_code,
        )

    def error_occurred(self, component: str, error: str, context: dict | None = None) -> None:
        """Log an error event.

        Args:
            component: Component where error occurred.
            error: Error message.
            context: Additional context.
        """
        self._log(
            "ERROR",
            component=component,
            error=error,
            context=context or {},
        )


# Global audit logger instance
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance.

    Returns:
        AuditLogger instance.
    """
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def reset_audit_logger() -> None:
    """Reset the global audit logger (for testing)."""
    global _audit_logger
    _audit_logger = None
