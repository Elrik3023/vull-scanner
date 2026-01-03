"""API request models."""

from pydantic import BaseModel, Field, field_validator
from typing import Optional


class ScanOptions(BaseModel):
    """Options for configuring a scan."""

    allow_private: bool = Field(
        default=False,
        description="Allow scanning private/internal IP ranges"
    )
    skip_ssl_verify: bool = Field(
        default=False,
        description="Skip SSL certificate verification"
    )
    min_threads: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Minimum number of threads for parallel operations"
    )
    max_threads: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Maximum number of threads for adaptive scaling"
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose logging for this scan"
    )

    @field_validator("max_threads")
    @classmethod
    def max_threads_gte_min_threads(cls, v, info):
        """Ensure max_threads >= min_threads."""
        if "min_threads" in info.data and v < info.data["min_threads"]:
            raise ValueError("max_threads must be >= min_threads")
        return v


class ScanRequest(BaseModel):
    """Request to create a new scan."""

    target: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Target URL or hostname to scan",
        examples=["example.com", "https://example.com"]
    )
    options: Optional[ScanOptions] = Field(
        default_factory=ScanOptions,
        description="Scan configuration options"
    )
    callback_url: Optional[str] = Field(
        default=None,
        description="Webhook URL to receive scan completion notification"
    )

    @field_validator("target")
    @classmethod
    def validate_target_format(cls, v):
        """Basic target format validation."""
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")

        # Block obviously dangerous inputs
        dangerous_patterns = ["<", ">", '"', "'", ";", "|", "&", "$", "`"]
        for pattern in dangerous_patterns:
            if pattern in v:
                raise ValueError(f"Invalid character in target: {pattern}")

        return v

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "target": "example.com",
                    "options": {
                        "allow_private": False,
                        "max_threads": 50
                    }
                }
            ]
        }
    }
