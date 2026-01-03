"""Celery worker for async scan execution."""

import os
from celery import Celery
from datetime import datetime

from vull_scanner.db.database import get_db_context
from vull_scanner.db.repositories import ScanRepository
from vull_scanner.db.models import ScanStatus, VulnerabilityType, VulnerabilitySeverity
from vull_scanner.utils.logging import setup_logging, get_logger

# Configure Celery
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "vull_scanner",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per scan
    task_soft_time_limit=3300,  # 55 minute soft limit
    worker_prefetch_multiplier=1,  # Only fetch one task at a time
    task_acks_late=True,  # Acknowledge after completion
    task_reject_on_worker_lost=True,  # Retry if worker dies
)

logger = get_logger("worker")


@celery_app.task(bind=True, name="vull_scanner.execute_scan")
def execute_scan(self, scan_id: str) -> dict:
    """Execute a vulnerability scan.

    This task runs the full vulnerability scanning workflow
    and updates the database with results.

    Args:
        scan_id: UUID of the scan to execute.

    Returns:
        Dict with scan results summary.
    """
    logger.info(f"Starting scan execution for {scan_id}")

    with get_db_context() as db:
        repo = ScanRepository(db)

        # Get scan from database
        scan = repo.get_by_id(scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return {"error": "Scan not found"}

        # Update status to running
        repo.update_status(scan_id, ScanStatus.RUNNING)
        repo.update_progress(scan_id, 0, "initializing")

        try:
            # Set up scan configuration from options
            options = scan.options or {}
            os.environ["VULL_MIN_THREADS"] = str(options.get("min_threads", 5))
            os.environ["VULL_MAX_THREADS"] = str(options.get("max_threads", 50))

            if options.get("skip_ssl_verify"):
                os.environ["VULL_SKIP_SSL_VERIFY"] = "true"

            # Check for OpenAI API key
            if not os.environ.get("OPENAI_API_KEY"):
                raise ValueError("OPENAI_API_KEY not configured")

            # Import scanner components
            from vull_scanner.graph import compile_scanner
            from vull_scanner.state import ScannerState

            # Update progress
            repo.update_progress(scan_id, 5, "compiling_scanner")

            # Compile the scanner graph
            scanner = compile_scanner()

            # Initialize state
            initial_state: ScannerState = {
                "target_url": scan.target,
                "allow_private": options.get("allow_private", False),
                "show_passwords": False,  # Never show passwords in worker
                "port_scan": None,
                "messages": [],
                "login_endpoints": [],
                "detected_technologies": [],
                "wordlist_selection": None,
                "nmap_result": None,
                "ffuf_result": None,
                "ffuf_results": [],
                "amass_result": None,
                "discovered_subdomains": [],
                "injectable_endpoints": [],
                "sqlmap_results": [],
                "burp_results": [],
                "credential_results": [],
                "errors": [],
                "current_phase": "init",
            }

            repo.update_progress(scan_id, 10, "scanning")

            # Run the scanner
            final_state = scanner.invoke(initial_state)

            # Process results
            repo.update_progress(scan_id, 90, "processing_results")

            # Save detected technologies
            for tech in final_state.get("detected_technologies", []):
                repo.add_technology(
                    scan_id,
                    name=tech.name,
                    confidence=tech.confidence,
                    evidence=tech.evidence,
                    version=tech.version,
                )

            # Save login endpoints
            for endpoint in final_state.get("login_endpoints", []):
                repo.add_login_endpoint(
                    scan_id,
                    url=endpoint.url,
                    method=endpoint.method,
                    form_fields=endpoint.form_fields,
                    csrf_field=endpoint.csrf_field,
                    additional_fields=endpoint.additional_fields,
                )

            # Save subdomains
            subdomains = final_state.get("discovered_subdomains", [])
            if subdomains:
                repo.set_subdomains(scan_id, subdomains)

            # Save credential findings as vulnerabilities
            for cred in final_state.get("credential_results", []):
                if cred.success:
                    repo.add_vulnerability(
                        scan_id,
                        vuln_type=VulnerabilityType.CREDENTIAL,
                        severity=VulnerabilitySeverity.CRITICAL,
                        title=f"Valid credentials found at {cred.endpoint_url}",
                        description=f"Username '{cred.username}' has valid credentials",
                        endpoint=cred.endpoint_url,
                        evidence=cred.evidence,
                        details={
                            "username": cred.username,
                            # Password intentionally not stored
                        }
                    )

            # Save SQL injection findings
            for sqli in final_state.get("sqlmap_results", []):
                if sqli.vulnerable:
                    for injection in sqli.injections:
                        repo.add_vulnerability(
                            scan_id,
                            vuln_type=VulnerabilityType.SQL_INJECTION,
                            severity=VulnerabilitySeverity.CRITICAL,
                            title=f"SQL Injection in parameter '{injection.parameter}'",
                            description=f"{injection.injection_type} SQL injection vulnerability",
                            endpoint=sqli.target_url,
                            evidence=f"DBMS: {injection.dbms}",
                            details={
                                "parameter": injection.parameter,
                                "injection_type": injection.injection_type,
                                "dbms": injection.dbms,
                            }
                        )

            # Store errors
            errors = final_state.get("errors", [])

            # Update final status
            repo.update_progress(scan_id, 100, "complete")
            repo.update_status(scan_id, ScanStatus.COMPLETED)

            # Refresh to get updated data
            scan = repo.get_by_id(scan_id)

            logger.info(
                f"Scan {scan_id} completed. "
                f"Vulnerabilities: {len(scan.vulnerabilities)}, "
                f"Technologies: {len(scan.technologies)}"
            )

            # TODO: Send webhook callback if configured
            if scan.callback_url:
                _send_callback(scan.callback_url, scan.to_dict())

            return {
                "scan_id": scan_id,
                "status": "completed",
                "vulnerabilities_found": len(scan.vulnerabilities),
                "technologies_found": len(scan.technologies),
                "login_endpoints_found": len(scan.login_endpoints),
            }

        except Exception as e:
            logger.exception(f"Scan {scan_id} failed: {e}")
            repo.update_status(scan_id, ScanStatus.FAILED, str(e))
            return {
                "scan_id": scan_id,
                "status": "failed",
                "error": str(e),
            }
        finally:
            # Always decrement concurrent scan counter
            try:
                from vull_scanner.api.rate_limiter import get_rate_limiter
                get_rate_limiter().decrement_concurrent_scans()
            except Exception:
                pass  # Rate limiter may not be available in worker context


@celery_app.task(name="vull_scanner.cancel_scan")
def cancel_scan(scan_id: str) -> dict:
    """Cancel a running scan.

    Args:
        scan_id: UUID of the scan to cancel.

    Returns:
        Dict with cancellation result.
    """
    logger.info(f"Cancelling scan {scan_id}")

    with get_db_context() as db:
        repo = ScanRepository(db)

        scan = repo.get_by_id(scan_id)
        if not scan:
            return {"error": "Scan not found"}

        if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
            return {"error": f"Cannot cancel scan with status {scan.status.value}"}

        repo.update_status(scan_id, ScanStatus.CANCELLED, "Cancelled by user")

        return {
            "scan_id": scan_id,
            "status": "cancelled",
        }


def _send_callback(url: str, data: dict) -> None:
    """Send webhook callback with scan results.

    Args:
        url: Webhook URL.
        data: Scan result data.
    """
    try:
        import httpx
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                url,
                json=data,
                headers={"Content-Type": "application/json"}
            )
            logger.info(f"Callback sent to {url}: {response.status_code}")
    except Exception as e:
        logger.warning(f"Failed to send callback to {url}: {e}")


# Celery beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    "reset-daily-api-usage": {
        "task": "vull_scanner.reset_daily_usage",
        "schedule": 86400.0,  # Once per day
    },
}


@celery_app.task(name="vull_scanner.reset_daily_usage")
def reset_daily_usage() -> dict:
    """Reset daily API usage counters."""
    from vull_scanner.db.repositories import APIKeyRepository

    with get_db_context() as db:
        repo = APIKeyRepository(db)
        count = repo.reset_daily_usage()
        logger.info(f"Reset daily usage for {count} API keys")
        return {"reset_count": count}
