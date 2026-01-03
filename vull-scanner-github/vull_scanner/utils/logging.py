"""Structured logging infrastructure for the vulnerability scanner."""

import logging
import json
import sys
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging to files."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_obj: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra fields if present
        if hasattr(record, "node"):
            log_obj["node"] = record.node
        if hasattr(record, "target"):
            log_obj["target"] = record.target
        if hasattr(record, "duration"):
            log_obj["duration"] = record.duration
        if hasattr(record, "findings"):
            log_obj["findings"] = record.findings

        # Add exception info if present
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


class ConsoleFormatter(logging.Formatter):
    """Console formatter with colors and clean output."""

    COLORS = {
        "DEBUG": "\033[36m",    # Cyan
        "INFO": "\033[32m",     # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",    # Red
        "CRITICAL": "\033[35m", # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        """Format log record for console output."""
        color = self.COLORS.get(record.levelname, self.RESET)

        # Build prefix based on level
        if record.levelname == "DEBUG":
            prefix = "[DEBUG]"
        elif record.levelname == "INFO":
            prefix = "[*]"
        elif record.levelname == "WARNING":
            prefix = "[!]"
        elif record.levelname == "ERROR":
            prefix = "[ERROR]"
        elif record.levelname == "CRITICAL":
            prefix = "[CRITICAL]"
        else:
            prefix = f"[{record.levelname}]"

        message = record.getMessage()

        # Add node context if present
        if hasattr(record, "node"):
            message = f"({record.node}) {message}"

        return f"{color}{prefix}{self.RESET} {message}"


_logger: logging.Logger | None = None


def setup_logging(
    verbose: bool = False,
    log_file: str | None = None,
    json_console: bool = False,
) -> logging.Logger:
    """Set up logging for the scanner.

    Args:
        verbose: Enable DEBUG level logging.
        log_file: Path to log file for JSON output.
        json_console: Use JSON format for console output.

    Returns:
        Configured logger.
    """
    global _logger

    level = logging.DEBUG if verbose else logging.INFO

    # Get root logger for vull_scanner
    logger = logging.getLogger("vull_scanner")
    logger.setLevel(level)

    # Clear any existing handlers
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    if json_console:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(ConsoleFormatter())

    logger.addHandler(console_handler)

    # File handler (always JSON format)
    if log_file:
        file_handler = logging.FileHandler(log_file, mode="a")
        file_handler.setLevel(logging.DEBUG)  # Always log everything to file
        file_handler.setFormatter(JSONFormatter())
        logger.addHandler(file_handler)

    # Prevent propagation to root logger
    logger.propagate = False

    _logger = logger
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger for a specific component.

    Args:
        name: Component name (e.g., 'nmap_scanner', 'credential_tester').

    Returns:
        Logger instance.
    """
    return logging.getLogger(f"vull_scanner.{name}")


def log_node_start(logger: logging.Logger, node_name: str, target: str) -> None:
    """Log the start of a node execution.

    Args:
        logger: Logger instance.
        node_name: Name of the node.
        target: Scan target.
    """
    logger.info(
        f"Starting {node_name}",
        extra={"node": node_name, "target": target},
    )


def log_node_complete(
    logger: logging.Logger,
    node_name: str,
    duration: float,
    findings: int = 0,
) -> None:
    """Log the completion of a node execution.

    Args:
        logger: Logger instance.
        node_name: Name of the node.
        duration: Execution time in seconds.
        findings: Number of findings.
    """
    logger.info(
        f"Completed {node_name} in {duration:.2f}s ({findings} findings)",
        extra={"node": node_name, "duration": duration, "findings": findings},
    )


def log_node_error(
    logger: logging.Logger,
    node_name: str,
    error: Exception,
    context: dict[str, Any] | None = None,
) -> None:
    """Log a node error.

    Args:
        logger: Logger instance.
        node_name: Name of the node.
        error: Exception that occurred.
        context: Additional context.
    """
    logger.error(
        f"Error in {node_name}: {error}",
        extra={"node": node_name, **(context or {})},
        exc_info=True,
    )
