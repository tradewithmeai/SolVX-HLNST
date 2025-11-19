"""Device resolver for identifying and tracking network devices."""

from typing import Optional, List, Dict, Any
from datetime import datetime

from sqlalchemy.orm import Session

from solvx_net.core.models import Device, Flow, TrustLevel
from solvx_net.core.logging import get_logger

logger = get_logger(__name__)


class DeviceResolver:
    """Resolve flows to devices and manage device inventory."""

    def __init__(self, db: Session):
        """
        Initialize device resolver.

        Args:
            db: Database session
        """
        self.db = db
        self._device_cache: Dict[str, Device] = {}
        self._load_cache()

    def _load_cache(self):
        """Load existing devices into cache."""
        devices = self.db.query(Device).all()
        for device in devices:
            self._device_cache[device.mac_address] = device
        logger.info(f"Loaded {len(self._device_cache)} devices into cache")

    def get_or_create_device(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> Device:
        """
        Get existing device or create new one.

        Args:
            mac_address: MAC address
            ip_address: IP address (optional)
            hostname: Hostname (optional)

        Returns:
            Device object
        """
        # Check cache first
        if mac_address in self._device_cache:
            device = self._device_cache[mac_address]

            # Update IP addresses if new
            if ip_address and ip_address not in device.ip_addresses:
                device.ip_addresses = device.ip_addresses + [ip_address]
                device.last_seen = datetime.utcnow()

            # Update hostname if provided
            if hostname and not device.hostname:
                device.hostname = hostname

            return device

        # Create new device
        device = Device(
            mac_address=mac_address,
            ip_addresses=[ip_address] if ip_address else [],
            hostname=hostname,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            trust_level=TrustLevel.UNKNOWN,
        )

        self.db.add(device)
        self.db.flush()  # Get ID
        self._device_cache[mac_address] = device

        logger.info(f"Created new device: {mac_address} (ID={device.id})")
        return device

    def resolve_flow_devices(self, flow: Flow) -> tuple[Optional[Device], Optional[Device]]:
        """
        Resolve source and destination devices for a flow.

        Args:
            flow: Flow object

        Returns:
            Tuple of (src_device, dst_device) (either may be None)
        """
        src_device = None
        dst_device = None

        # Resolve source device
        if flow.src_mac:
            src_device = self.get_or_create_device(
                mac_address=flow.src_mac,
                ip_address=flow.src_ip,
            )
            flow.src_device_id = src_device.id

        # Resolve destination device
        if flow.dst_mac:
            dst_device = self.get_or_create_device(
                mac_address=flow.dst_mac,
                ip_address=flow.dst_ip,
            )
            flow.dst_device_id = dst_device.id

        return src_device, dst_device

    def resolve_flows_batch(self, flows: List[Flow]) -> int:
        """
        Resolve devices for a batch of flows.

        Args:
            flows: List of flows

        Returns:
            Number of devices resolved
        """
        resolved_count = 0

        for flow in flows:
            src_dev, dst_dev = self.resolve_flow_devices(flow)
            if src_dev or dst_dev:
                resolved_count += 1

        self.db.flush()
        logger.info(f"Resolved devices for {resolved_count} flows")
        return resolved_count

    def update_device_last_seen(self, device_id: int, timestamp: datetime):
        """
        Update device last seen timestamp.

        Args:
            device_id: Device ID
            timestamp: Timestamp
        """
        device = self.db.query(Device).filter(Device.id == device_id).first()
        if device and (not device.last_seen or timestamp > device.last_seen):
            device.last_seen = timestamp

    def get_device_by_mac(self, mac_address: str) -> Optional[Device]:
        """
        Get device by MAC address.

        Args:
            mac_address: MAC address

        Returns:
            Device or None
        """
        return self._device_cache.get(mac_address) or self.db.query(Device).filter(
            Device.mac_address == mac_address
        ).first()

    def get_device_by_ip(self, ip_address: str) -> Optional[Device]:
        """
        Get device by IP address.

        Args:
            ip_address: IP address

        Returns:
            Device or None (if multiple devices have the IP, returns most recent)
        """
        # Check cache
        for device in self._device_cache.values():
            if ip_address in device.ip_addresses:
                return device

        # Query database
        devices = self.db.query(Device).all()
        for device in devices:
            if ip_address in device.ip_addresses:
                return device

        return None

    def get_all_devices(self) -> List[Device]:
        """
        Get all devices.

        Returns:
            List of devices
        """
        return list(self._device_cache.values())

    def update_device_trust_level(self, device_id: int, trust_level: TrustLevel):
        """
        Update device trust level.

        Args:
            device_id: Device ID
            trust_level: New trust level
        """
        device = self.db.query(Device).filter(Device.id == device_id).first()
        if device:
            device.trust_level = trust_level
            logger.info(f"Updated device {device_id} trust level to {trust_level}")

    def add_device_tag(self, device_id: int, tag: str):
        """
        Add tag to device.

        Args:
            device_id: Device ID
            tag: Tag to add
        """
        device = self.db.query(Device).filter(Device.id == device_id).first()
        if device:
            if tag not in device.tags:
                device.tags = device.tags + [tag]
                logger.info(f"Added tag '{tag}' to device {device_id}")

    def remove_device_tag(self, device_id: int, tag: str):
        """
        Remove tag from device.

        Args:
            device_id: Device ID
            tag: Tag to remove
        """
        device = self.db.query(Device).filter(Device.id == device_id).first()
        if device and tag in device.tags:
            tags = list(device.tags)
            tags.remove(tag)
            device.tags = tags
            logger.info(f"Removed tag '{tag}' from device {device_id}")
