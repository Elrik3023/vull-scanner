"""Prometheus metrics for the VULL Scanner API."""

import time
from functools import wraps
from typing import Callable

from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Application info
APP_INFO = Info("vull_scanner", "VULL Scanner application information")
APP_INFO.info({
    "version": "0.1.0",
    "name": "vull-scanner",
})

# Request metrics
REQUEST_COUNT = Counter(
    "vull_scanner_requests_total",
    "Total number of HTTP requests",
    ["method", "endpoint", "status_code"]
)

REQUEST_LATENCY = Histogram(
    "vull_scanner_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

REQUEST_IN_PROGRESS = Gauge(
    "vull_scanner_requests_in_progress",
    "Number of HTTP requests currently being processed",
    ["method", "endpoint"]
)

# Scan metrics
SCANS_TOTAL = Counter(
    "vull_scanner_scans_total",
    "Total number of scans submitted",
    ["status"]
)

SCANS_IN_PROGRESS = Gauge(
    "vull_scanner_scans_in_progress",
    "Number of scans currently running"
)

SCAN_DURATION = Histogram(
    "vull_scanner_scan_duration_seconds",
    "Scan execution time in seconds",
    buckets=[10, 30, 60, 120, 300, 600, 1200, 3600]
)

VULNERABILITIES_FOUND = Counter(
    "vull_scanner_vulnerabilities_total",
    "Total number of vulnerabilities discovered",
    ["severity", "type"]
)

# External tool metrics
EXTERNAL_TOOL_CALLS = Counter(
    "vull_scanner_external_tool_calls_total",
    "Number of calls to external tools",
    ["tool", "status"]
)

EXTERNAL_TOOL_DURATION = Histogram(
    "vull_scanner_external_tool_duration_seconds",
    "External tool execution time in seconds",
    ["tool"],
    buckets=[1, 5, 10, 30, 60, 120, 300]
)

# API key metrics
API_KEY_USAGE = Counter(
    "vull_scanner_api_key_requests_total",
    "Number of requests per API key",
    ["key_id"]
)

RATE_LIMIT_EXCEEDED = Counter(
    "vull_scanner_rate_limit_exceeded_total",
    "Number of rate limit exceeded errors",
    ["key_id", "limit_type"]
)

CONCURRENT_SCANS = Gauge(
    "vull_scanner_concurrent_scans",
    "Current number of concurrent scans running"
)

# Database metrics
DB_QUERY_DURATION = Histogram(
    "vull_scanner_db_query_duration_seconds",
    "Database query execution time",
    ["operation"],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
)

# Credential testing metrics
CREDENTIAL_TESTS = Counter(
    "vull_scanner_credential_tests_total",
    "Total number of credential tests performed",
    ["result"]
)


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware for collecting HTTP request metrics."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and collect metrics."""
        method = request.method
        # Normalize endpoint path for metrics
        endpoint = self._normalize_path(request.url.path)

        # Track in-progress requests
        REQUEST_IN_PROGRESS.labels(method=method, endpoint=endpoint).inc()

        start_time = time.time()
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as e:
            status_code = 500
            raise
        finally:
            # Record metrics
            duration = time.time() - start_time

            REQUEST_COUNT.labels(
                method=method,
                endpoint=endpoint,
                status_code=status_code
            ).inc()

            REQUEST_LATENCY.labels(
                method=method,
                endpoint=endpoint
            ).observe(duration)

            REQUEST_IN_PROGRESS.labels(method=method, endpoint=endpoint).dec()

        return response

    def _normalize_path(self, path: str) -> str:
        """Normalize path for consistent metrics labels.

        Replaces dynamic path segments (UUIDs, IDs) with placeholders.
        """
        import re

        # Replace UUIDs
        path = re.sub(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "{id}",
            path
        )

        # Replace numeric IDs
        path = re.sub(r"/\d+(/|$)", "/{id}\\1", path)

        return path


def record_scan_started():
    """Record that a scan has started."""
    SCANS_TOTAL.labels(status="started").inc()
    SCANS_IN_PROGRESS.inc()


def record_scan_completed(duration_seconds: float, status: str = "completed"):
    """Record that a scan has completed.

    Args:
        duration_seconds: How long the scan took.
        status: Final status (completed, failed, cancelled).
    """
    SCANS_TOTAL.labels(status=status).inc()
    SCANS_IN_PROGRESS.dec()
    SCAN_DURATION.observe(duration_seconds)


def record_vulnerability(severity: str, vuln_type: str):
    """Record a discovered vulnerability.

    Args:
        severity: Vulnerability severity (critical, high, medium, low, info).
        vuln_type: Type of vulnerability.
    """
    VULNERABILITIES_FOUND.labels(severity=severity, type=vuln_type).inc()


def record_external_tool_call(tool: str, success: bool, duration: float):
    """Record an external tool execution.

    Args:
        tool: Tool name (nmap, ffuf, sqlmap, amass).
        success: Whether the call succeeded.
        duration: Execution time in seconds.
    """
    status = "success" if success else "failure"
    EXTERNAL_TOOL_CALLS.labels(tool=tool, status=status).inc()
    EXTERNAL_TOOL_DURATION.labels(tool=tool).observe(duration)


def record_credential_test(success: bool):
    """Record a credential test result.

    Args:
        success: Whether the credential was valid.
    """
    result = "success" if success else "failure"
    CREDENTIAL_TESTS.labels(result=result).inc()


def record_api_key_usage(key_id: str):
    """Record API key usage.

    Args:
        key_id: The API key ID.
    """
    API_KEY_USAGE.labels(key_id=key_id).inc()


def record_rate_limit_exceeded(key_id: str, limit_type: str = "request"):
    """Record rate limit exceeded event.

    Args:
        key_id: The API key ID that exceeded limits.
        limit_type: Type of limit exceeded (request, daily_scan, concurrent).
    """
    RATE_LIMIT_EXCEEDED.labels(key_id=key_id, limit_type=limit_type).inc()


def update_concurrent_scans(count: int):
    """Update the concurrent scans gauge.

    Args:
        count: Current number of concurrent scans.
    """
    CONCURRENT_SCANS.set(count)


async def metrics_endpoint(request: Request) -> Response:
    """Endpoint that returns Prometheus metrics."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )
