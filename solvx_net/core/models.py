"""Database models for SolVX Network Security Toolkit."""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Text,
    Float,
    Boolean,
    ForeignKey,
    JSON,
    Enum as SQLEnum,
)
from sqlalchemy.orm import relationship
import enum

from solvx_net.core.database import Base


class TrustLevel(str, enum.Enum):
    """Device trust level."""

    TRUSTED = "trusted"
    GUEST = "guest"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"


class CaptureType(str, enum.Enum):
    """Capture source type."""

    OFFLINE_PCAP = "offline_pcap"
    LIVE = "live"


class AlertType(str, enum.Enum):
    """Alert type classification."""

    DNS_LEAK = "DNS_LEAK"
    ARP_SPOOF = "ARP_SPOOF"
    ROGUE_DEVICE = "ROGUE_DEVICE"
    PORT_SCAN = "PORT_SCAN"
    SUSPICIOUS_TRAFFIC = "SUSPICIOUS_TRAFFIC"
    MITM_DETECTED = "MITM_DETECTED"


class AlertSeverity(str, enum.Enum):
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    """Alert status."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Device(Base):
    """Network device model."""

    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String(17), unique=True, nullable=False, index=True)
    ip_addresses = Column(JSON, default=list)  # List of IP addresses
    hostname = Column(String(255), nullable=True)
    vendor = Column(String(255), nullable=True)  # From OUI lookup
    os_guess = Column(String(255), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    trust_level = Column(SQLEnum(TrustLevel), default=TrustLevel.UNKNOWN, nullable=False)
    tags = Column(JSON, default=list)  # e.g., ["IoT", "server", "mobile"]
    extra_metadata = Column(JSON, default=dict)  # Additional device info

    # Relationships
    alerts = relationship("Alert", back_populates="device")
    threat_scores = relationship("ThreatScoreSnapshot", back_populates="device")
    src_flows = relationship("Flow", foreign_keys="Flow.src_device_id", back_populates="src_device")
    dst_flows = relationship("Flow", foreign_keys="Flow.dst_device_id", back_populates="dst_device")

    def __repr__(self):
        return f"<Device(mac={self.mac_address}, hostname={self.hostname}, trust={self.trust_level})>"


class Capture(Base):
    """Packet capture session model."""

    __tablename__ = "captures"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(SQLEnum(CaptureType), nullable=False)
    source = Column(String(512), nullable=False)  # File path or interface name
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=True)
    num_packets = Column(Integer, default=0)
    num_flows = Column(Integer, default=0)
    notes = Column(Text, nullable=True)
    extra_metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    flows = relationship("Flow", back_populates="capture", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Capture(type={self.type}, source={self.source}, packets={self.num_packets})>"


class Flow(Base):
    """Network flow model."""

    __tablename__ = "flows"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(Integer, ForeignKey("captures.id"), nullable=False, index=True)

    src_ip = Column(String(45), nullable=False, index=True)  # IPv4 or IPv6
    src_port = Column(Integer, nullable=True)
    src_mac = Column(String(17), nullable=True)
    src_device_id = Column(Integer, ForeignKey("devices.id"), nullable=True, index=True)

    dst_ip = Column(String(45), nullable=False, index=True)
    dst_port = Column(Integer, nullable=True)
    dst_mac = Column(String(17), nullable=True)
    dst_device_id = Column(Integer, ForeignKey("devices.id"), nullable=True, index=True)

    protocol = Column(String(10), nullable=False)  # TCP, UDP, ICMP, etc.
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)

    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)

    # Additional metadata (JA3, SNI, DNS info, etc.)
    flags = Column(String(50), nullable=True)  # TCP flags
    extra_metadata = Column(JSON, default=dict)

    # Relationships
    capture = relationship("Capture", back_populates="flows")
    src_device = relationship("Device", foreign_keys=[src_device_id], back_populates="src_flows")
    dst_device = relationship("Device", foreign_keys=[dst_device_id], back_populates="dst_flows")

    def __repr__(self):
        return f"<Flow({self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} [{self.protocol}])>"


class Alert(Base):
    """Security alert model."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True, index=True)

    alert_type = Column(SQLEnum(AlertType), nullable=False, index=True)
    severity = Column(SQLEnum(AlertSeverity), nullable=False, index=True)
    score = Column(Integer, default=0)  # 0-100

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(JSON, default=dict)  # Flow IDs, packet refs, etc.

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(SQLEnum(AlertStatus), default=AlertStatus.OPEN, nullable=False, index=True)

    # Relationships
    device = relationship("Device", back_populates="alerts")

    def __repr__(self):
        return f"<Alert({self.alert_type}, severity={self.severity}, status={self.status})>"


class ThreatScoreSnapshot(Base):
    """Threat score snapshot model."""

    __tablename__ = "threat_score_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True, index=True)

    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    score = Column(Float, nullable=False)  # 0-100
    details = Column(JSON, default=dict)  # Breakdown of contributing factors

    # Relationships
    device = relationship("Device", back_populates="threat_scores")

    def __repr__(self):
        return f"<ThreatScore(device_id={self.device_id}, score={self.score:.2f})>"


class Rule(Base):
    """Detection rule model."""

    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True)
    category = Column(String(100), nullable=False)
    severity = Column(SQLEnum(AlertSeverity), nullable=False)
    rule_type = Column(String(50), nullable=False)  # python_function, threshold, pattern
    config = Column(JSON, default=dict)
    enabled = Column(Boolean, default=True)
    description = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Rule({self.name}, category={self.category}, enabled={self.enabled})>"


class ARPEntry(Base):
    """ARP table entry for spoofing detection."""

    __tablename__ = "arp_entries"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    mac_address = Column(String(17), nullable=False)
    operation = Column(String(20), nullable=False)  # request, reply
    seen_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    capture_id = Column(Integer, ForeignKey("captures.id"), nullable=True)

    def __repr__(self):
        return f"<ARPEntry({self.ip_address} -> {self.mac_address})>"
