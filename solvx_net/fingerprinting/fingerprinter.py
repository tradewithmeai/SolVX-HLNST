"""Device fingerprinting using traffic patterns and heuristics."""

from typing import List, Set, Dict, Any, Optional
from collections import Counter

from sqlalchemy.orm import Session

from solvx_net.core.models import Device, Flow
from solvx_net.core.logging import get_logger
from solvx_net.fingerprinting.oui import get_oui_lookup

logger = get_logger(__name__)


class DeviceProfile:
    """Device traffic profile for fingerprinting."""

    def __init__(self, device: Device, flows: List[Flow]):
        """
        Initialize device profile.

        Args:
            device: Device object
            flows: List of flows involving this device
        """
        self.device = device
        self.flows = flows

        # Calculate profile metrics
        self.protocols: Counter = Counter()
        self.ports_used: Set[int] = set()
        self.services_accessed: Set[int] = set()
        self.dns_queries: List[str] = []

        self._analyze_flows()

    def _analyze_flows(self):
        """Analyze flows to build profile."""
        for flow in self.flows:
            # Count protocols
            self.protocols[flow.protocol] += 1

            # Collect ports
            if flow.src_device_id == self.device.id and flow.src_port:
                self.ports_used.add(flow.src_port)
            if flow.dst_device_id == self.device.id and flow.dst_port:
                self.services_accessed.add(flow.dst_port)

            # Extract DNS queries
            if flow.extra_metadata and "dns_queries" in flow.extra_metadata:
                self.dns_queries.extend(flow.extra_metadata["dns_queries"])

    def has_tcp_service(self, port: int) -> bool:
        """Check if device is running TCP service on port."""
        return port in self.services_accessed

    def uses_port(self, port: int) -> bool:
        """Check if device uses specific port."""
        return port in self.ports_used or port in self.services_accessed

    def protocol_ratio(self, protocol: str) -> float:
        """Get ratio of specific protocol."""
        if not self.protocols:
            return 0.0
        return self.protocols[protocol] / sum(self.protocols.values())


class DeviceFingerprinter:
    """Fingerprint devices based on traffic patterns."""

    def __init__(self, db: Session):
        """
        Initialize fingerprinter.

        Args:
            db: Database session
        """
        self.db = db
        self.oui_lookup = get_oui_lookup()

    def fingerprint_device(self, device: Device) -> Dict[str, Any]:
        """
        Fingerprint a device.

        Args:
            device: Device to fingerprint

        Returns:
            Fingerprinting results
        """
        logger.info(f"Fingerprinting device {device.id} ({device.mac_address})")

        # Get vendor from OUI
        vendor = self.oui_lookup.lookup(device.mac_address)
        if vendor:
            device.vendor = vendor

        # Get flows for this device
        flows = (
            self.db.query(Flow)
            .filter(
                (Flow.src_device_id == device.id) | (Flow.dst_device_id == device.id)
            )
            .all()
        )

        if not flows:
            logger.info(f"No flows found for device {device.id}, limited fingerprinting")
            return {
                "device_id": device.id,
                "vendor": vendor,
                "os_guess": None,
                "device_type": "Unknown",
                "confidence": "low",
            }

        # Build profile
        profile = DeviceProfile(device, flows)

        # Apply heuristics
        os_guess = self._guess_os(device, profile)
        device_type = self._guess_device_type(device, profile)
        tags = self._suggest_tags(device, profile)

        # Update device
        if os_guess:
            device.os_guess = os_guess

        # Add suggested tags
        for tag in tags:
            if tag not in device.tags:
                device.tags = device.tags + [tag]

        result = {
            "device_id": device.id,
            "vendor": vendor,
            "os_guess": os_guess,
            "device_type": device_type,
            "tags": tags,
            "confidence": self._calculate_confidence(profile),
            "profile_summary": {
                "total_flows": len(flows),
                "protocols": dict(profile.protocols),
                "common_ports": list(profile.services_accessed)[:10],
            },
        }

        logger.info(f"Fingerprinted device {device.id}: {device_type} ({os_guess})")
        return result

    def _guess_os(self, device: Device, profile: DeviceProfile) -> Optional[str]:
        """
        Guess operating system.

        Args:
            device: Device object
            profile: Device profile

        Returns:
            OS guess or None
        """
        vendor = device.vendor or ""

        # Apple devices
        if "Apple" in vendor:
            # Check for common Apple ports/services
            if profile.uses_port(5353):  # Bonjour
                return "macOS/iOS"
            return "Apple Device"

        # Windows indicators
        if profile.has_tcp_service(445) or profile.has_tcp_service(139):  # SMB
            return "Windows"
        if profile.has_tcp_service(3389):  # RDP
            return "Windows"

        # Linux indicators
        if profile.has_tcp_service(22):  # SSH
            if "Raspberry" in vendor:
                return "Linux (Raspberry Pi OS)"
            return "Linux"

        # IoT devices (minimal traffic patterns)
        if len(profile.protocols) <= 2 and profile.protocol_ratio("TCP") < 0.3:
            return "Embedded/IoT"

        return None

    def _guess_device_type(self, device: Device, profile: DeviceProfile) -> str:
        """
        Guess device type.

        Args:
            device: Device object
            profile: Device profile

        Returns:
            Device type
        """
        vendor = device.vendor or ""

        # Known device types from vendor
        if "Raspberry" in vendor:
            return "Single Board Computer"

        if "Camera" in vendor or "Hikvision" in vendor or "Dahua" in vendor:
            return "IP Camera"

        # Server indicators
        if any(profile.has_tcp_service(p) for p in [80, 443, 22, 3306, 5432, 6379]):
            return "Server"

        # Router/Gateway indicators
        if profile.has_tcp_service(53) and profile.has_tcp_service(67):
            return "Router/Gateway"

        # Mobile device indicators (high HTTPS, moderate traffic)
        if profile.protocol_ratio("TCP") > 0.7 and profile.uses_port(443):
            if "Apple" in vendor:
                return "Mobile (iOS)"
            if "Samsung" in vendor or "Google" in vendor:
                return "Mobile (Android)"
            return "Mobile Device"

        # Desktop/Laptop indicators
        if profile.has_tcp_service(445) or profile.has_tcp_service(22):
            return "Desktop/Laptop"

        # IoT indicators
        if len(profile.protocols) <= 2 and len(profile.flows) < 100:
            return "IoT Device"

        # Smart TV / Streaming device
        if profile.uses_port(443) and len(profile.dns_queries) > 10:
            streaming_domains = ["netflix", "youtube", "hulu", "roku", "amazon"]
            if any(domain in "".join(profile.dns_queries).lower() for domain in streaming_domains):
                return "Smart TV/Streaming"

        return "Unknown"

    def _suggest_tags(self, device: Device, profile: DeviceProfile) -> List[str]:
        """
        Suggest tags for device.

        Args:
            device: Device object
            profile: Device profile

        Returns:
            List of suggested tags
        """
        tags = []

        # Protocol-based tags
        if profile.protocol_ratio("UDP") > 0.5:
            tags.append("udp-heavy")

        # Service-based tags
        if profile.has_tcp_service(22):
            tags.append("ssh-server")
        if profile.has_tcp_service(80) or profile.has_tcp_service(443):
            tags.append("web-server")
        if profile.has_tcp_service(3306) or profile.has_tcp_service(5432):
            tags.append("database-server")

        # Activity level
        if len(profile.flows) > 1000:
            tags.append("high-activity")
        elif len(profile.flows) < 10:
            tags.append("low-activity")

        return tags

    def _calculate_confidence(self, profile: DeviceProfile) -> str:
        """
        Calculate confidence level of fingerprinting.

        Args:
            profile: Device profile

        Returns:
            Confidence level (low/medium/high)
        """
        if len(profile.flows) == 0:
            return "none"
        elif len(profile.flows) < 10:
            return "low"
        elif len(profile.flows) < 100:
            return "medium"
        else:
            return "high"

    def fingerprint_all_devices(self) -> List[Dict[str, Any]]:
        """
        Fingerprint all devices in database.

        Returns:
            List of fingerprinting results
        """
        devices = self.db.query(Device).all()
        results = []

        logger.info(f"Fingerprinting {len(devices)} devices...")

        for device in devices:
            try:
                result = self.fingerprint_device(device)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to fingerprint device {device.id}: {e}")

        self.db.commit()
        logger.info(f"Fingerprinted {len(results)} devices successfully")

        return results
