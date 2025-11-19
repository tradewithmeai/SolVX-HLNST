"""Rogue device detection engine."""

from typing import List
from datetime import datetime, timedelta
import ipaddress

from sqlalchemy.orm import Session

from solvx_net.core.models import Device, Flow, TrustLevel, AlertType, AlertSeverity
from solvx_net.core.config import get_config
from solvx_net.detections.base import BaseDetector, DetectionResult


class RogueDeviceDetector(BaseDetector):
    """Detect rogue/unauthorized devices on the network."""

    @property
    def name(self) -> str:
        return "Rogue Device Detector"

    @property
    def description(self) -> str:
        return "Detects unauthorized or suspicious devices on the network"

    def detect(self) -> List[DetectionResult]:
        """Run rogue device detection."""
        results = []
        config = get_config()

        # Get all unknown and untrusted devices
        suspicious_devices = (
            self.db.query(Device)
            .filter(Device.trust_level.in_([TrustLevel.UNKNOWN, TrustLevel.BLOCKED]))
            .all()
        )

        for device in suspicious_devices:
            # Skip if already has recent alert
            if self._has_recent_alert(device.id):
                continue

            # Check various rogue indicators
            is_rogue, reason, evidence = self._is_rogue_device(device)

            if is_rogue:
                severity = (
                    AlertSeverity.CRITICAL
                    if device.trust_level == TrustLevel.BLOCKED
                    else AlertSeverity.HIGH
                )

                results.append(
                    DetectionResult(
                        alert_type=AlertType.ROGUE_DEVICE,
                        severity=severity,
                        title=f"Rogue Device Detected: {device.mac_address}",
                        description=f"Device {device.mac_address} ({device.vendor or 'Unknown vendor'}) "
                        f"detected on network. Reason: {reason}",
                        device_id=device.id,
                        evidence=evidence,
                        score=70 if severity == AlertSeverity.HIGH else 90,
                    )
                )

        return results

    def _is_rogue_device(self, device: Device) -> tuple[bool, str, dict]:
        """
        Check if device is rogue.

        Returns:
            Tuple of (is_rogue, reason, evidence)
        """
        config = get_config()
        evidence = {
            "mac_address": device.mac_address,
            "ip_addresses": device.ip_addresses,
            "vendor": device.vendor,
            "first_seen": device.first_seen.isoformat(),
            "last_seen": device.last_seen.isoformat(),
        }

        # Check 1: Device is explicitly blocked
        if device.trust_level == TrustLevel.BLOCKED:
            return True, "Device is on blocklist", evidence

        # Check 2: Unknown device with high activity
        if device.trust_level == TrustLevel.UNKNOWN:
            flow_count = (
                self.db.query(Flow)
                .filter(
                    (Flow.src_device_id == device.id) | (Flow.dst_device_id == device.id)
                )
                .count()
            )

            if flow_count > 100:
                evidence["flow_count"] = flow_count
                return (
                    True,
                    f"Unknown device with high activity ({flow_count} flows)",
                    evidence,
                )

        # Check 3: Device in non-guest IP range but not trusted
        if device.ip_addresses and device.trust_level != TrustLevel.GUEST:
            for ip in device.ip_addresses:
                if not self._is_guest_ip(ip):
                    # Non-guest IP range, should be trusted
                    recent_time = datetime.utcnow() - timedelta(hours=24)
                    if device.first_seen > recent_time:
                        # New device in trusted range
                        evidence["ip_range"] = "trusted_range"
                        return (
                            True,
                            "New device appeared in trusted IP range",
                            evidence,
                        )

        # Check 4: Unknown vendor with network scanning behavior
        if not device.vendor or device.vendor == "Unknown":
            # Check for port scanning activity
            unique_dst_ports = set()
            flows = (
                self.db.query(Flow)
                .filter(Flow.src_device_id == device.id)
                .limit(1000)
                .all()
            )

            for flow in flows:
                if flow.dst_port:
                    unique_dst_ports.add(flow.dst_port)

            if len(unique_dst_ports) > 50:
                evidence["unique_ports_accessed"] = len(unique_dst_ports)
                return (
                    True,
                    f"Unknown vendor device scanning many ports ({len(unique_dst_ports)})",
                    evidence,
                )

        return False, "", evidence

    def _is_guest_ip(self, ip: str) -> bool:
        """Check if IP is in guest range."""
        config = get_config()
        guest_ranges = config.detection.guest_ip_ranges

        try:
            ip_obj = ipaddress.ip_address(ip)
            for range_str in guest_ranges:
                if "-" in range_str:
                    # Range format: 192.168.1.100-192.168.1.200
                    start_str, end_str = range_str.split("-")
                    start_ip = ipaddress.ip_address(start_str.strip())
                    end_ip = ipaddress.ip_address(end_str.strip())
                    if start_ip <= ip_obj <= end_ip:
                        return True
                else:
                    # CIDR format
                    network = ipaddress.ip_network(range_str, strict=False)
                    if ip_obj in network:
                        return True
        except ValueError:
            pass

        return False

    def _has_recent_alert(self, device_id: int, hours: int = 24) -> bool:
        """Check if device has recent rogue device alert."""
        from solvx_net.core.models import Alert

        recent_time = datetime.utcnow() - timedelta(hours=hours)
        alert = (
            self.db.query(Alert)
            .filter(
                Alert.device_id == device_id,
                Alert.alert_type == AlertType.ROGUE_DEVICE,
                Alert.created_at > recent_time,
            )
            .first()
        )

        return alert is not None
