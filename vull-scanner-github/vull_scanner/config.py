"""Configuration management for VULL Scanner.

Configuration sources (in priority order):
1. CLI arguments
2. Environment variables
3. Config file (YAML/TOML)
4. Default values
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any
import logging

logger = logging.getLogger("vull_scanner.config")


@dataclass
class ThreadingConfig:
    """Threading configuration."""

    min_threads: int = 5
    max_threads: int = 50
    scale_interval: float = 30.0  # Seconds between scaling checks


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""

    request_delay: float = 0.1  # Seconds between requests
    max_requests_per_minute: int = 600
    max_concurrent_scans: int = 10


@dataclass
class TimeoutConfig:
    """Timeout configuration."""

    http_timeout: float = 10.0  # HTTP request timeout
    tool_timeout: float = 300.0  # External tool timeout
    scan_timeout: float = 3600.0  # Max scan duration


@dataclass
class SecurityConfig:
    """Security configuration."""

    verify_ssl: bool = True
    allow_private_ips: bool = False
    mask_passwords: bool = True
    audit_logging: bool = True


@dataclass
class WordlistConfig:
    """Wordlist configuration."""

    max_usernames: int = 500
    max_passwords: int = 1000
    max_usernames_per_file: int = 100
    max_passwords_per_file: int = 200
    seclists_paths: list[str] = field(default_factory=lambda: [
        "/usr/share/seclists",
        "~/SecLists",
        "/opt/seclists",
        "/usr/share/wordlists/seclists",
    ])


@dataclass
class DatabaseConfig:
    """Database configuration."""

    url: str = "sqlite:///./vull_scanner.db"
    pool_size: int = 5
    max_overflow: int = 10
    pool_pre_ping: bool = True
    echo: bool = False


@dataclass
class RedisConfig:
    """Redis configuration for Celery."""

    url: str = "redis://localhost:6379/0"
    max_connections: int = 10


@dataclass
class APIConfig:
    """API configuration."""

    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    debug: bool = False
    cors_origins: list[str] = field(default_factory=lambda: ["*"])


@dataclass
class JWTConfig:
    """JWT configuration."""

    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    expiration_hours: int = 24


@dataclass
class ScannerConfig:
    """Complete scanner configuration."""

    # Sub-configurations
    threading: ThreadingConfig = field(default_factory=ThreadingConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    timeout: TimeoutConfig = field(default_factory=TimeoutConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    wordlist: WordlistConfig = field(default_factory=WordlistConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)
    api: APIConfig = field(default_factory=APIConfig)
    jwt: JWTConfig = field(default_factory=JWTConfig)

    # OpenAI configuration
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o"

    @classmethod
    def from_env(cls) -> "ScannerConfig":
        """Load configuration from environment variables.

        Returns:
            ScannerConfig populated from environment.
        """
        config = cls()

        # Threading
        config.threading.min_threads = int(os.environ.get("VULL_MIN_THREADS", config.threading.min_threads))
        config.threading.max_threads = int(os.environ.get("VULL_MAX_THREADS", config.threading.max_threads))

        # Rate limiting
        config.rate_limit.request_delay = float(os.environ.get("VULL_REQUEST_DELAY", config.rate_limit.request_delay))

        # Timeouts
        config.timeout.http_timeout = float(os.environ.get("VULL_HTTP_TIMEOUT", config.timeout.http_timeout))
        config.timeout.tool_timeout = float(os.environ.get("VULL_TOOL_TIMEOUT", config.timeout.tool_timeout))
        config.timeout.scan_timeout = float(os.environ.get("VULL_SCAN_TIMEOUT", config.timeout.scan_timeout))

        # Security
        skip_ssl = os.environ.get("VULL_SKIP_SSL_VERIFY", "").lower()
        config.security.verify_ssl = skip_ssl not in ("true", "1", "yes")
        config.security.allow_private_ips = os.environ.get("VULL_ALLOW_PRIVATE", "").lower() in ("true", "1", "yes")

        # Wordlists
        config.wordlist.max_usernames = int(os.environ.get("VULL_MAX_USERNAMES", config.wordlist.max_usernames))
        config.wordlist.max_passwords = int(os.environ.get("VULL_MAX_PASSWORDS", config.wordlist.max_passwords))

        # Database
        config.database.url = os.environ.get("DATABASE_URL", config.database.url)
        config.database.echo = os.environ.get("SQL_DEBUG", "").lower() == "true"

        # Redis
        config.redis.url = os.environ.get("REDIS_URL", config.redis.url)

        # API
        config.api.host = os.environ.get("API_HOST", config.api.host)
        config.api.port = int(os.environ.get("API_PORT", config.api.port))
        config.api.debug = os.environ.get("API_DEBUG", "").lower() == "true"

        # JWT
        config.jwt.secret_key = os.environ.get("JWT_SECRET_KEY", config.jwt.secret_key)
        config.jwt.expiration_hours = int(os.environ.get("JWT_EXPIRATION_HOURS", config.jwt.expiration_hours))

        # OpenAI
        config.openai_api_key = os.environ.get("OPENAI_API_KEY")
        config.openai_model = os.environ.get("OPENAI_MODEL", config.openai_model)

        return config

    @classmethod
    def from_file(cls, path: str) -> "ScannerConfig":
        """Load configuration from a YAML or TOML file.

        Args:
            path: Path to configuration file.

        Returns:
            ScannerConfig populated from file.
        """
        config_path = Path(path)

        if not config_path.exists():
            logger.warning(f"Config file not found: {path}, using defaults")
            return cls()

        if config_path.suffix in (".yaml", ".yml"):
            return cls._load_yaml(config_path)
        elif config_path.suffix == ".toml":
            return cls._load_toml(config_path)
        else:
            logger.warning(f"Unknown config format: {config_path.suffix}, using defaults")
            return cls()

    @classmethod
    def _load_yaml(cls, path: Path) -> "ScannerConfig":
        """Load configuration from YAML file."""
        try:
            import yaml

            with open(path) as f:
                data = yaml.safe_load(f)

            return cls._from_dict(data or {})
        except ImportError:
            logger.warning("PyYAML not installed, cannot load YAML config")
            return cls()
        except Exception as e:
            logger.error(f"Error loading YAML config: {e}")
            return cls()

    @classmethod
    def _load_toml(cls, path: Path) -> "ScannerConfig":
        """Load configuration from TOML file."""
        try:
            import tomllib

            with open(path, "rb") as f:
                data = tomllib.load(f)

            return cls._from_dict(data or {})
        except ImportError:
            logger.warning("tomllib not available, cannot load TOML config")
            return cls()
        except Exception as e:
            logger.error(f"Error loading TOML config: {e}")
            return cls()

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> "ScannerConfig":
        """Create config from dictionary."""
        config = cls()

        # Threading
        if "threading" in data:
            t = data["threading"]
            config.threading.min_threads = t.get("min_threads", config.threading.min_threads)
            config.threading.max_threads = t.get("max_threads", config.threading.max_threads)
            config.threading.scale_interval = t.get("scale_interval", config.threading.scale_interval)

        # Rate limiting
        if "rate_limit" in data:
            r = data["rate_limit"]
            config.rate_limit.request_delay = r.get("request_delay", config.rate_limit.request_delay)
            config.rate_limit.max_requests_per_minute = r.get("max_requests_per_minute", config.rate_limit.max_requests_per_minute)

        # Timeouts
        if "timeout" in data:
            t = data["timeout"]
            config.timeout.http_timeout = t.get("http_timeout", config.timeout.http_timeout)
            config.timeout.tool_timeout = t.get("tool_timeout", config.timeout.tool_timeout)
            config.timeout.scan_timeout = t.get("scan_timeout", config.timeout.scan_timeout)

        # Security
        if "security" in data:
            s = data["security"]
            config.security.verify_ssl = s.get("verify_ssl", config.security.verify_ssl)
            config.security.allow_private_ips = s.get("allow_private_ips", config.security.allow_private_ips)
            config.security.mask_passwords = s.get("mask_passwords", config.security.mask_passwords)

        # Wordlist
        if "wordlist" in data:
            w = data["wordlist"]
            config.wordlist.max_usernames = w.get("max_usernames", config.wordlist.max_usernames)
            config.wordlist.max_passwords = w.get("max_passwords", config.wordlist.max_passwords)

        # Database
        if "database" in data:
            d = data["database"]
            config.database.url = d.get("url", config.database.url)
            config.database.pool_size = d.get("pool_size", config.database.pool_size)

        # Redis
        if "redis" in data:
            r = data["redis"]
            config.redis.url = r.get("url", config.redis.url)

        # API
        if "api" in data:
            a = data["api"]
            config.api.host = a.get("host", config.api.host)
            config.api.port = a.get("port", config.api.port)
            config.api.debug = a.get("debug", config.api.debug)

        # JWT
        if "jwt" in data:
            j = data["jwt"]
            config.jwt.secret_key = j.get("secret_key", config.jwt.secret_key)
            config.jwt.expiration_hours = j.get("expiration_hours", config.jwt.expiration_hours)

        # OpenAI
        config.openai_api_key = data.get("openai_api_key", config.openai_api_key)
        config.openai_model = data.get("openai_model", config.openai_model)

        return config

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "threading": {
                "min_threads": self.threading.min_threads,
                "max_threads": self.threading.max_threads,
                "scale_interval": self.threading.scale_interval,
            },
            "rate_limit": {
                "request_delay": self.rate_limit.request_delay,
                "max_requests_per_minute": self.rate_limit.max_requests_per_minute,
                "max_concurrent_scans": self.rate_limit.max_concurrent_scans,
            },
            "timeout": {
                "http_timeout": self.timeout.http_timeout,
                "tool_timeout": self.timeout.tool_timeout,
                "scan_timeout": self.timeout.scan_timeout,
            },
            "security": {
                "verify_ssl": self.security.verify_ssl,
                "allow_private_ips": self.security.allow_private_ips,
                "mask_passwords": self.security.mask_passwords,
                "audit_logging": self.security.audit_logging,
            },
            "wordlist": {
                "max_usernames": self.wordlist.max_usernames,
                "max_passwords": self.wordlist.max_passwords,
            },
            "api": {
                "host": self.api.host,
                "port": self.api.port,
                "debug": self.api.debug,
            },
        }


# Global configuration instance
_config: Optional[ScannerConfig] = None


def get_config() -> ScannerConfig:
    """Get the global configuration.

    Loads from environment on first access.

    Returns:
        Global ScannerConfig instance.
    """
    global _config

    if _config is None:
        # Check for config file
        config_file = os.environ.get("VULL_CONFIG_FILE")
        if config_file:
            _config = ScannerConfig.from_file(config_file)
        else:
            _config = ScannerConfig.from_env()

    return _config


def reset_config() -> None:
    """Reset the global configuration.

    Useful for testing.
    """
    global _config
    _config = None
