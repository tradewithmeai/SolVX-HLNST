"""Pydantic schemas for API."""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel


# Device schemas
class DeviceBase(BaseModel):
    mac_address: str
    ip_addresses: List[str]
    hostname: Optional[str]
    vendor: Optional[str]
    os_guess: Optional[str]
    trust_level: str
    tags: List[str]


class Device(DeviceBase):
    id: int
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True


# Capture schemas
class CaptureBase(BaseModel):
    type: str
    source: str
    num_packets: int
    num_flows: int
    notes: Optional[str]


class Capture(CaptureBase):
    id: int
    start_time: datetime
    end_time: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


# Flow schemas
class FlowBase(BaseModel):
    src_ip: str
    src_port: Optional[int]
    dst_ip: str
    dst_port: Optional[int]
    protocol: str
    packet_count: int
    byte_count: int


class Flow(FlowBase):
    id: int
    capture_id: int
    start_time: datetime
    end_time: datetime
    src_device_id: Optional[int]
    dst_device_id: Optional[int]

    class Config:
        from_attributes = True


# Alert schemas
class AlertBase(BaseModel):
    alert_type: str
    severity: str
    title: str
    description: str
    score: int
    status: str


class Alert(AlertBase):
    id: int
    device_id: Optional[int]
    evidence: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Threat score schemas
class ThreatScore(BaseModel):
    device_id: int
    score: float
    alert_count: int
    breakdown: Dict[str, float]
    trust_level: str
    risk_level: str


class NetworkHealth(BaseModel):
    network_score: float
    health_status: str
    total_devices: int
    high_risk_devices: int
    medium_risk_devices: int
    low_risk_devices: int
    safe_devices: int
    total_alerts_24h: int
    critical_open_alerts: int


# Statistics schemas
class Statistics(BaseModel):
    total_devices: int
    total_captures: int
    total_flows: int
    total_alerts: int
    open_alerts: int
    critical_alerts: int


# Pagination
class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    pages: int
