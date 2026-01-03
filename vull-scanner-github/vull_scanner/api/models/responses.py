"""API response models."""

from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime
from enum import Enum


class ScanStatus(str, Enum):
    """Possible scan statuses."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnerabilitySeverity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities."""
    CREDENTIAL = "credential"
    SQL_INJECTION = "sql_injection"
    EXPOSED_ENDPOINT = "exposed_endpoint"
    INFORMATION_DISCLOSURE = "information_disclosure"
    MISCONFIGURATION = "misconfiguration"


class ScanResponse(BaseModel):
    """Response when creating a new scan."""

    id: str = Field(
        ...,
        description="Unique scan identifier"
    )
    target: str = Field(
        ...,
        description="Target being scanned"
    )
    status: ScanStatus = Field(
        default=ScanStatus.PENDING,
        description="Current scan status"
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the scan was created"
    )
    message: str = Field(
        default="Scan queued successfully",
        description="Status message"
    )


class ScanStatusResponse(BaseModel):
    """Response with scan status information."""

    id: str = Field(
        ...,
        description="Unique scan identifier"
    )
    target: str = Field(
        ...,
        description="Target being scanned"
    )
    status: ScanStatus = Field(
        ...,
        description="Current scan status"
    )
    progress: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
        description="Scan progress percentage (0-100)"
    )
    current_phase: Optional[str] = Field(
        default=None,
        description="Current scanning phase"
    )
    created_at: datetime = Field(
        ...,
        description="When the scan was created"
    )
    started_at: Optional[datetime] = Field(
        default=None,
        description="When the scan started running"
    )
    completed_at: Optional[datetime] = Field(
        default=None,
        description="When the scan completed"
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error message if scan failed"
    )
    vulnerabilities_found: int = Field(
        default=0,
        ge=0,
        description="Number of vulnerabilities found so far"
    )


class VulnerabilityResponse(BaseModel):
    """Individual vulnerability details."""

    id: str = Field(
        ...,
        description="Unique vulnerability identifier"
    )
    type: VulnerabilityType = Field(
        ...,
        description="Type of vulnerability"
    )
    severity: VulnerabilitySeverity = Field(
        ...,
        description="Severity level"
    )
    title: str = Field(
        ...,
        description="Brief vulnerability title"
    )
    description: str = Field(
        ...,
        description="Detailed description"
    )
    endpoint: Optional[str] = Field(
        default=None,
        description="Affected endpoint URL"
    )
    evidence: Optional[str] = Field(
        default=None,
        description="Evidence of the vulnerability"
    )
    details: Optional[dict[str, Any]] = Field(
        default=None,
        description="Additional details specific to vulnerability type"
    )
    discovered_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the vulnerability was discovered"
    )


class TechnologyResponse(BaseModel):
    """Detected technology information."""

    name: str = Field(
        ...,
        description="Technology name"
    )
    version: Optional[str] = Field(
        default=None,
        description="Version if detected"
    )
    confidence: str = Field(
        ...,
        description="Detection confidence (high, medium, low)"
    )
    evidence: str = Field(
        ...,
        description="What indicated this technology"
    )


class ScanResultsResponse(BaseModel):
    """Complete scan results."""

    id: str = Field(
        ...,
        description="Unique scan identifier"
    )
    target: str = Field(
        ...,
        description="Scanned target"
    )
    status: ScanStatus = Field(
        ...,
        description="Final scan status"
    )
    created_at: datetime = Field(
        ...,
        description="When the scan was created"
    )
    completed_at: Optional[datetime] = Field(
        default=None,
        description="When the scan completed"
    )
    duration_seconds: Optional[float] = Field(
        default=None,
        description="Total scan duration in seconds"
    )
    vulnerabilities: list[VulnerabilityResponse] = Field(
        default_factory=list,
        description="List of discovered vulnerabilities"
    )
    technologies: list[TechnologyResponse] = Field(
        default_factory=list,
        description="Detected technologies"
    )
    subdomains: list[str] = Field(
        default_factory=list,
        description="Discovered subdomains"
    )
    login_endpoints: list[str] = Field(
        default_factory=list,
        description="Discovered login endpoints"
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Errors encountered during scan"
    )
    summary: Optional[str] = Field(
        default=None,
        description="Human-readable summary of findings"
    )

    @property
    def vulnerability_count(self) -> int:
        """Total number of vulnerabilities."""
        return len(self.vulnerabilities)

    @property
    def critical_count(self) -> int:
        """Number of critical vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL)


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(
        default="healthy",
        description="Service health status"
    )
    version: str = Field(
        default="0.1.0",
        description="API version"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Current server time"
    )
    checks: dict[str, bool] = Field(
        default_factory=dict,
        description="Individual health checks"
    )


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(
        ...,
        description="Error type"
    )
    message: str = Field(
        ...,
        description="Human-readable error message"
    )
    details: Optional[dict[str, Any]] = Field(
        default=None,
        description="Additional error details"
    )
