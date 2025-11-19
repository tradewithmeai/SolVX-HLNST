"""Configuration management using Pydantic."""

from pathlib import Path
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseConfig(BaseSettings):
    """Database configuration."""

    url: str = Field(
        default="sqlite:///~/.solvx/solvx.db",
        description="Database URL (SQLite or PostgreSQL)",
    )
    echo: bool = Field(default=False, description="Echo SQL queries")


class CaptureConfig(BaseSettings):
    """Packet capture configuration."""

    interface: Optional[str] = Field(default=None, description="Network interface for live capture")
    pcap_dir: Path = Field(
        default=Path("~/.solvx/pcaps").expanduser(),
        description="Directory to store PCAP files",
    )
    rotate_size_mb: int = Field(default=100, description="PCAP rotation size in MB")
    rotate_interval_minutes: int = Field(default=15, description="PCAP rotation interval in minutes")


class DetectionConfig(BaseSettings):
    """Detection engine configuration."""

    # Rogue device detection
    enable_rogue_detection: bool = Field(default=True, description="Enable rogue device detection")
    trusted_mac_prefixes: List[str] = Field(
        default_factory=list,
        description="Trusted MAC prefixes (OUI)",
    )
    guest_ip_ranges: List[str] = Field(
        default_factory=lambda: ["192.168.1.100-192.168.1.200"],
        description="Guest IP ranges",
    )

    # ARP spoofing detection
    enable_arp_detection: bool = Field(default=True, description="Enable ARP spoofing detection")
    gateway_ip: Optional[str] = Field(default=None, description="Gateway IP to monitor")
    gateway_mac: Optional[str] = Field(default=None, description="Gateway MAC to monitor")
    arp_window_minutes: int = Field(default=5, description="Time window for ARP analysis")

    # DNS leak detection
    enable_dns_leak_detection: bool = Field(default=True, description="Enable DNS leak detection")
    allowed_dns_servers: List[str] = Field(
        default_factory=list,
        description="Allowed DNS server IPs",
    )
    flag_public_dns: bool = Field(
        default=False,
        description="Flag queries to public DNS servers (8.8.8.8, 1.1.1.1, etc)",
    )


class ScoringConfig(BaseSettings):
    """Threat scoring configuration."""

    alert_weights: dict = Field(
        default_factory=lambda: {
            "ARP_SPOOF": 90,
            "DNS_LEAK": 60,
            "ROGUE_DEVICE": 70,
            "PORT_SCAN": 80,
            "SUSPICIOUS_TRAFFIC": 50,
        },
        description="Base severity scores for alert types",
    )
    recency_weight: float = Field(default=0.7, description="Weight for recent alerts (0-1)")
    frequency_weight: float = Field(default=0.3, description="Weight for alert frequency (0-1)")
    score_window_hours: int = Field(default=24, description="Time window for score calculation")


class APIConfig(BaseSettings):
    """API server configuration."""

    host: str = Field(default="127.0.0.1", description="API server host")
    port: int = Field(default=8000, description="API server port")
    reload: bool = Field(default=False, description="Auto-reload on code changes")
    workers: int = Field(default=1, description="Number of worker processes")
    auth_token: Optional[str] = Field(default=None, description="Simple auth token")


class Config(BaseSettings):
    """Main application configuration."""

    model_config = SettingsConfigDict(
        env_prefix="SOLVX_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    # Application settings
    app_name: str = Field(default="SolVX Network Security Toolkit", description="Application name")
    log_level: str = Field(default="INFO", description="Logging level")
    log_dir: Path = Field(
        default=Path("~/.solvx/logs").expanduser(),
        description="Log directory",
    )
    data_dir: Path = Field(
        default=Path("~/.solvx/data").expanduser(),
        description="Data directory",
    )

    # Sub-configurations
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    api: APIConfig = Field(default_factory=APIConfig)

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.capture.pcap_dir.mkdir(parents=True, exist_ok=True)


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get or create global config instance."""
    global _config
    if _config is None:
        _config = Config()
        _config.ensure_directories()
    return _config


def set_config(config: Config) -> None:
    """Set global config instance (useful for testing)."""
    global _config
    _config = config
