"""SQLAlchemy database models."""

import uuid
from datetime import datetime
from typing import Optional, Any

from sqlalchemy import (
    Column,
    String,
    Text,
    Integer,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    Enum as SQLEnum,
    JSON,
    Index,
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.postgresql import UUID

import enum


Base = declarative_base()


def generate_uuid() -> str:
    """Generate a new UUID string."""
    return str(uuid.uuid4())


class ScanStatus(enum.Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnerabilitySeverity(enum.Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(enum.Enum):
    """Types of vulnerabilities."""
    CREDENTIAL = "credential"
    SQL_INJECTION = "sql_injection"
    EXPOSED_ENDPOINT = "exposed_endpoint"
    INFORMATION_DISCLOSURE = "information_disclosure"
    MISCONFIGURATION = "misconfiguration"


class Scan(Base):
    """Scan job record."""

    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target = Column(String(255), nullable=False, index=True)
    original_target = Column(String(255), nullable=True)

    status = Column(
        SQLEnum(ScanStatus),
        default=ScanStatus.PENDING,
        nullable=False,
        index=True
    )

    # Scan options (stored as JSON)
    options = Column(JSON, default=dict)

    # Webhook callback
    callback_url = Column(String(2048), nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Progress tracking
    progress = Column(Integer, default=0)
    current_phase = Column(String(50), nullable=True)

    # Error information
    error_message = Column(Text, nullable=True)

    # Discovered data (stored as JSON for flexibility)
    subdomains = Column(JSON, default=list)
    raw_results = Column(JSON, default=dict)

    # Relationships
    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan"
    )
    technologies = relationship(
        "Technology",
        back_populates="scan",
        cascade="all, delete-orphan"
    )
    login_endpoints = relationship(
        "LoginEndpoint",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

    # Indexes
    __table_args__ = (
        Index("ix_scans_status_created", "status", "created_at"),
    )

    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate scan duration in seconds."""
        if self.completed_at and self.started_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status.value if self.status else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "progress": self.progress,
            "current_phase": self.current_phase,
            "error_message": self.error_message,
            "vulnerabilities_count": len(self.vulnerabilities) if self.vulnerabilities else 0,
        }


class Vulnerability(Base):
    """Discovered vulnerability."""

    __tablename__ = "vulnerabilities"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    type = Column(SQLEnum(VulnerabilityType), nullable=False)
    severity = Column(SQLEnum(VulnerabilitySeverity), nullable=False, index=True)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    endpoint = Column(String(2048), nullable=True)
    evidence = Column(Text, nullable=True)

    # Additional details as JSON
    details = Column(JSON, default=dict)

    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationship
    scan = relationship("Scan", back_populates="vulnerabilities")

    # Indexes
    __table_args__ = (
        Index("ix_vuln_scan_severity", "scan_id", "severity"),
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.type.value if self.type else None,
            "severity": self.severity.value if self.severity else None,
            "title": self.title,
            "description": self.description,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "details": self.details,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }


class Technology(Base):
    """Detected technology."""

    __tablename__ = "technologies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    name = Column(String(100), nullable=False)
    version = Column(String(50), nullable=True)
    confidence = Column(String(20), nullable=False)  # high, medium, low
    evidence = Column(Text, nullable=True)

    # Relationship
    scan = relationship("Scan", back_populates="technologies")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


class LoginEndpoint(Base):
    """Discovered login endpoint."""

    __tablename__ = "login_endpoints"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    url = Column(String(2048), nullable=False)
    method = Column(String(10), default="POST")
    form_fields = Column(JSON, default=list)
    csrf_field = Column(String(100), nullable=True)
    additional_fields = Column(JSON, default=dict)

    # Relationship
    scan = relationship("Scan", back_populates="login_endpoints")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "method": self.method,
            "form_fields": self.form_fields,
            "csrf_field": self.csrf_field,
        }


class APIKey(Base):
    """API key for authentication."""

    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    name = Column(String(100), nullable=False)

    # Permissions
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)

    # Rate limiting
    rate_limit_daily = Column(Integer, default=100)
    rate_limit_concurrent = Column(Integer, default=10)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)

    # Usage tracking
    scans_today = Column(Integer, default=0)
    scans_total = Column(Integer, default=0)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (excluding sensitive data)."""
        return {
            "id": self.id,
            "name": self.name,
            "is_active": self.is_active,
            "is_admin": self.is_admin,
            "rate_limit_daily": self.rate_limit_daily,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
        }
