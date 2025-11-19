"""OUI (Organizationally Unique Identifier) lookup for MAC vendor identification."""

from typing import Optional, Dict
import re

from solvx_net.core.logging import get_logger

logger = get_logger(__name__)


# Common OUI database (subset of vendors - can be expanded or loaded from file)
OUI_DATABASE = {
    # Apple
    "00:03:93": "Apple",
    "00:0A:27": "Apple",
    "00:0A:95": "Apple",
    "00:0D:93": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:CB": "Apple",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1B:63": "Apple",
    "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",
    "00:1E:52": "Apple",
    "00:1F:5B": "Apple",
    "00:1F:F3": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    # Samsung
    "00:00:F0": "Samsung",
    "00:02:78": "Samsung",
    "00:07:AB": "Samsung",
    "00:09:18": "Samsung",
    "00:0D:AE": "Samsung",
    "00:12:47": "Samsung",
    "00:12:FB": "Samsung",
    "00:13:77": "Samsung",
    "00:15:99": "Samsung",
    "00:15:B9": "Samsung",
    "00:16:32": "Samsung",
    "00:16:6B": "Samsung",
    "00:16:6C": "Samsung",
    "00:17:C9": "Samsung",
    "00:17:D5": "Samsung",
    "00:18:AF": "Samsung",
    "00:1A:8A": "Samsung",
    "00:1B:98": "Samsung",
    "00:1C:43": "Samsung",
    "00:1D:25": "Samsung",
    # Intel
    "00:02:B3": "Intel",
    "00:03:47": "Intel",
    "00:04:23": "Intel",
    "00:07:E9": "Intel",
    "00:0C:F1": "Intel",
    "00:0E:0C": "Intel",
    "00:11:11": "Intel",
    "00:12:F0": "Intel",
    "00:13:02": "Intel",
    "00:13:20": "Intel",
    "00:13:CE": "Intel",
    "00:13:E8": "Intel",
    "00:15:00": "Intel",
    "00:16:6F": "Intel",
    "00:16:76": "Intel",
    "00:16:EA": "Intel",
    "00:16:EB": "Intel",
    "00:18:DE": "Intel",
    "00:19:D1": "Intel",
    "00:19:D2": "Intel",
    # Cisco
    "00:00:0C": "Cisco",
    "00:01:42": "Cisco",
    "00:01:43": "Cisco",
    "00:01:63": "Cisco",
    "00:01:64": "Cisco",
    "00:01:96": "Cisco",
    "00:01:97": "Cisco",
    "00:01:C7": "Cisco",
    "00:02:16": "Cisco",
    "00:02:17": "Cisco",
    "00:02:3D": "Cisco",
    "00:02:4A": "Cisco",
    "00:02:4B": "Cisco",
    # TP-Link
    "00:27:19": "TP-Link",
    "10:FE:ED": "TP-Link",
    "14:CF:92": "TP-Link",
    "18:A6:F7": "TP-Link",
    "1C:3B:F3": "TP-Link",
    "50:C7:BF": "TP-Link",
    "54:A5:1B": "TP-Link",
    "60:E3:27": "TP-Link",
    "74:EA:3A": "TP-Link",
    "84:16:F9": "TP-Link",
    "A4:2B:8C": "TP-Link",
    "B0:95:8E": "TP-Link",
    "C0:4A:00": "TP-Link",
    # Raspberry Pi
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    # Google
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "54:60:09": "Google",
    "68:C4:4D": "Google",
    "6C:AD:F8": "Google",
    "74:E5:43": "Google",
    "A4:77:33": "Google",
    "CC:3A:61": "Google",
    "F4:F5:D8": "Google",
    # Amazon
    "00:17:88": "Amazon Technologies",
    "44:65:0D": "Amazon Technologies",
    "68:37:E9": "Amazon Technologies",
    "74:C2:46": "Amazon Technologies",
    "84:D6:D0": "Amazon Technologies",
    "FC:A6:67": "Amazon Technologies",
}


def normalize_mac(mac: str) -> str:
    """
    Normalize MAC address to standard format (XX:XX:XX:XX:XX:XX).

    Args:
        mac: MAC address in various formats

    Returns:
        Normalized MAC address
    """
    # Remove common separators and convert to uppercase
    mac_clean = re.sub(r"[.:\-\s]", "", mac.upper())

    # Add colons every 2 characters
    if len(mac_clean) == 12:
        return ":".join([mac_clean[i:i+2] for i in range(0, 12, 2)])

    return mac


def get_oui_prefix(mac: str) -> str:
    """
    Extract OUI prefix (first 3 octets) from MAC address.

    Args:
        mac: MAC address

    Returns:
        OUI prefix (XX:XX:XX)
    """
    normalized = normalize_mac(mac)
    return ":".join(normalized.split(":")[:3])


def lookup_vendor(mac: str) -> Optional[str]:
    """
    Look up vendor name from MAC address.

    Args:
        mac: MAC address

    Returns:
        Vendor name or None if not found
    """
    if not mac:
        return None

    oui_prefix = get_oui_prefix(mac)
    vendor = OUI_DATABASE.get(oui_prefix)

    if vendor:
        logger.debug(f"OUI lookup: {mac} -> {vendor}")
    else:
        logger.debug(f"OUI lookup: {mac} -> Unknown")

    return vendor


def is_local_mac(mac: str) -> bool:
    """
    Check if MAC address is locally administered.

    Args:
        mac: MAC address

    Returns:
        True if locally administered
    """
    normalized = normalize_mac(mac)
    if not normalized:
        return False

    # Check second character of first octet (bit 1 of first byte)
    first_octet = int(normalized[:2], 16)
    return bool(first_octet & 0x02)


def is_multicast_mac(mac: str) -> bool:
    """
    Check if MAC address is multicast.

    Args:
        mac: MAC address

    Returns:
        True if multicast
    """
    normalized = normalize_mac(mac)
    if not normalized:
        return False

    # Check first character of first octet (bit 0 of first byte)
    first_octet = int(normalized[:2], 16)
    return bool(first_octet & 0x01)


class OUILookup:
    """OUI lookup service."""

    def __init__(self):
        """Initialize OUI lookup."""
        self.database = OUI_DATABASE
        logger.info(f"Initialized OUI lookup with {len(self.database)} entries")

    def lookup(self, mac: str) -> Optional[str]:
        """
        Look up vendor for MAC address.

        Args:
            mac: MAC address

        Returns:
            Vendor name or None
        """
        return lookup_vendor(mac)

    def get_vendor_or_unknown(self, mac: str) -> str:
        """
        Look up vendor or return "Unknown".

        Args:
            mac: MAC address

        Returns:
            Vendor name or "Unknown"
        """
        vendor = self.lookup(mac)
        return vendor or "Unknown"

    def get_vendor_with_flags(self, mac: str) -> Dict[str, any]:
        """
        Get vendor with additional MAC address flags.

        Args:
            mac: MAC address

        Returns:
            Dictionary with vendor and flags
        """
        return {
            "vendor": self.lookup(mac),
            "is_local": is_local_mac(mac),
            "is_multicast": is_multicast_mac(mac),
            "oui_prefix": get_oui_prefix(mac),
        }


# Global OUI lookup instance
_oui_lookup = None


def get_oui_lookup() -> OUILookup:
    """Get global OUI lookup instance."""
    global _oui_lookup
    if _oui_lookup is None:
        _oui_lookup = OUILookup()
    return _oui_lookup
