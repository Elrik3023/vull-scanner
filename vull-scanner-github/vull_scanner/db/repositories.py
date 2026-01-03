"""Repository pattern for database operations."""

from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from vull_scanner.db.models import (
    Scan,
    Vulnerability,
    Technology,
    LoginEndpoint,
    APIKey,
    ScanStatus,
    VulnerabilitySeverity,
    VulnerabilityType,
)


class ScanRepository:
    """Repository for Scan operations."""

    def __init__(self, db: Session):
        self.db = db

    def create(
        self,
        target: str,
        options: dict = None,
        callback_url: str = None,
        original_target: str = None,
    ) -> Scan:
        """Create a new scan record."""
        scan = Scan(
            target=target,
            original_target=original_target or target,
            options=options or {},
            callback_url=callback_url,
            status=ScanStatus.PENDING,
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def get_by_id(self, scan_id: str) -> Optional[Scan]:
        """Get a scan by ID."""
        return self.db.query(Scan).filter(Scan.id == scan_id).first()

    def list_all(
        self,
        status: Optional[ScanStatus] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Scan]:
        """List scans with optional filtering."""
        query = self.db.query(Scan)

        if status:
            query = query.filter(Scan.status == status)

        return (
            query
            .order_by(Scan.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    def update_status(
        self,
        scan_id: str,
        status: ScanStatus,
        error_message: str = None,
    ) -> Optional[Scan]:
        """Update scan status."""
        scan = self.get_by_id(scan_id)
        if not scan:
            return None

        scan.status = status

        if status == ScanStatus.RUNNING and not scan.started_at:
            scan.started_at = datetime.utcnow()
        elif status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
            scan.completed_at = datetime.utcnow()

        if error_message:
            scan.error_message = error_message

        self.db.commit()
        self.db.refresh(scan)
        return scan

    def update_progress(
        self,
        scan_id: str,
        progress: int,
        current_phase: str = None,
    ) -> Optional[Scan]:
        """Update scan progress."""
        scan = self.get_by_id(scan_id)
        if not scan:
            return None

        scan.progress = min(100, max(0, progress))
        if current_phase:
            scan.current_phase = current_phase

        self.db.commit()
        self.db.refresh(scan)
        return scan

    def add_vulnerability(
        self,
        scan_id: str,
        vuln_type: VulnerabilityType,
        severity: VulnerabilitySeverity,
        title: str,
        description: str = None,
        endpoint: str = None,
        evidence: str = None,
        details: dict = None,
    ) -> Optional[Vulnerability]:
        """Add a vulnerability to a scan."""
        scan = self.get_by_id(scan_id)
        if not scan:
            return None

        vuln = Vulnerability(
            scan_id=scan_id,
            type=vuln_type,
            severity=severity,
            title=title,
            description=description,
            endpoint=endpoint,
            evidence=evidence,
            details=details or {},
        )
        self.db.add(vuln)
        self.db.commit()
        self.db.refresh(vuln)
        return vuln

    def add_technology(
        self,
        scan_id: str,
        name: str,
        confidence: str,
        evidence: str = None,
        version: str = None,
    ) -> Optional[Technology]:
        """Add a detected technology to a scan."""
        scan = self.get_by_id(scan_id)
        if not scan:
            return None

        tech = Technology(
            scan_id=scan_id,
            name=name,
            version=version,
            confidence=confidence,
            evidence=evidence,
        )
        self.db.add(tech)
        self.db.commit()
        self.db.refresh(tech)
        return tech

    def add_login_endpoint(
        self,
        scan_id: str,
        url: str,
        method: str = "POST",
        form_fields: list = None,
        csrf_field: str = None,
        additional_fields: dict = None,
    ) -> Optional[LoginEndpoint]:
        """Add a login endpoint to a scan."""
        scan = self.get_by_id(scan_id)
        if not scan:
            return None

        endpoint = LoginEndpoint(
            scan_id=scan_id,
            url=url,
            method=method,
            form_fields=form_fields or [],
            csrf_field=csrf_field,
            additional_fields=additional_fields or {},
        )
        self.db.add(endpoint)
        self.db.commit()
        self.db.refresh(endpoint)
        return endpoint

    def set_subdomains(self, scan_id: str, subdomains: list[str]) -> Optional[Scan]:
        """Set discovered subdomains for a scan."""
        scan = self.get_by_id(scan_id)
        if not scan:
            return None

        scan.subdomains = subdomains
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def delete(self, scan_id: str) -> bool:
        """Delete a scan and all related data."""
        scan = self.get_by_id(scan_id)
        if not scan:
            return False

        self.db.delete(scan)
        self.db.commit()
        return True


class APIKeyRepository:
    """Repository for API key operations."""

    def __init__(self, db: Session):
        self.db = db

    def create(
        self,
        key_hash: str,
        name: str,
        is_admin: bool = False,
        rate_limit_daily: int = 100,
        rate_limit_concurrent: int = 10,
    ) -> APIKey:
        """Create a new API key."""
        api_key = APIKey(
            key_hash=key_hash,
            name=name,
            is_admin=is_admin,
            rate_limit_daily=rate_limit_daily,
            rate_limit_concurrent=rate_limit_concurrent,
        )
        self.db.add(api_key)
        self.db.commit()
        self.db.refresh(api_key)
        return api_key

    def get_by_hash(self, key_hash: str) -> Optional[APIKey]:
        """Get an API key by its hash."""
        return (
            self.db.query(APIKey)
            .filter(APIKey.key_hash == key_hash)
            .filter(APIKey.is_active == True)
            .first()
        )

    def get_by_id(self, key_id: str) -> Optional[APIKey]:
        """Get an API key by ID."""
        return self.db.query(APIKey).filter(APIKey.id == key_id).first()

    def record_usage(self, key_id: str) -> Optional[APIKey]:
        """Record API key usage."""
        api_key = self.get_by_id(key_id)
        if not api_key:
            return None

        api_key.last_used_at = datetime.utcnow()
        api_key.scans_today += 1
        api_key.scans_total += 1

        self.db.commit()
        self.db.refresh(api_key)
        return api_key

    def reset_daily_usage(self) -> int:
        """Reset daily usage for all keys. Returns count of keys reset."""
        result = (
            self.db.query(APIKey)
            .filter(APIKey.scans_today > 0)
            .update({APIKey.scans_today: 0})
        )
        self.db.commit()
        return result

    def deactivate(self, key_id: str) -> bool:
        """Deactivate an API key."""
        api_key = self.get_by_id(key_id)
        if not api_key:
            return False

        api_key.is_active = False
        self.db.commit()
        return True

    def list_all(self, include_inactive: bool = False) -> list[APIKey]:
        """List all API keys."""
        query = self.db.query(APIKey)
        if not include_inactive:
            query = query.filter(APIKey.is_active == True)
        return query.order_by(APIKey.created_at.desc()).all()
