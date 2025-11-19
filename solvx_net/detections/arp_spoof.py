"""ARP spoofing and MITM detection engine."""

from typing import List, Dict
from datetime import datetime, timedelta
from collections import defaultdict

from sqlalchemy.orm import Session
from sqlalchemy import and_

from solvx_net.core.models import ARPEntry, Flow, AlertType, AlertSeverity
from solvx_net.core.config import get_config
from solvx_net.detections.base import BaseDetector, DetectionResult


class ARPSpoofDetector(BaseDetector):
    """Detect ARP spoofing and MITM attacks."""

    @property
    def name(self) -> str:
        return "ARP Spoof Detector"

    @property
    def description(self) -> str:
        return "Detects ARP spoofing and potential MITM attacks"

    def detect(self) -> List[DetectionResult]:
        """Run ARP spoofing detection."""
        results = []
        config = get_config()

        # Check for IP-MAC conflicts
        results.extend(self._detect_ip_mac_conflicts())

        # Check for gateway MAC changes
        if config.detection.gateway_ip:
            results.extend(self._detect_gateway_mac_change(config.detection.gateway_ip))

        # Check for unusual ARP activity
        results.extend(self._detect_arp_anomalies())

        return results

    def _detect_ip_mac_conflicts(self) -> List[DetectionResult]:
        """Detect same IP mapping to multiple MACs."""
        results = []
        window_minutes = get_config().detection.arp_window_minutes
        window_start = datetime.utcnow() - timedelta(minutes=window_minutes)

        # Get recent ARP entries
        arp_entries = (
            self.db.query(ARPEntry)
            .filter(ARPEntry.seen_at > window_start)
            .order_by(ARPEntry.seen_at.desc())
            .all()
        )

        # Group by IP
        ip_mac_map: Dict[str, set] = defaultdict(set)
        ip_first_seen: Dict[str, datetime] = {}

        for entry in arp_entries:
            ip_mac_map[entry.ip_address].add(entry.mac_address)
            if entry.ip_address not in ip_first_seen:
                ip_first_seen[entry.ip_address] = entry.seen_at

        # Check for conflicts
        for ip, macs in ip_mac_map.items():
            if len(macs) > 1:
                # Same IP with multiple MACs - possible ARP spoofing
                evidence = {
                    "ip_address": ip,
                    "mac_addresses": list(macs),
                    "conflict_count": len(macs),
                    "window_minutes": window_minutes,
                    "first_seen": ip_first_seen[ip].isoformat(),
                }

                results.append(
                    DetectionResult(
                        alert_type=AlertType.ARP_SPOOF,
                        severity=AlertSeverity.CRITICAL,
                        title=f"ARP Spoofing Detected: IP {ip}",
                        description=f"IP address {ip} is being claimed by {len(macs)} different MAC addresses. "
                        f"This indicates possible ARP spoofing or MITM attack. "
                        f"MACs: {', '.join(macs)}",
                        evidence=evidence,
                        score=90,
                    )
                )

        return results

    def _detect_gateway_mac_change(self, gateway_ip: str) -> List[DetectionResult]:
        """Detect changes in gateway MAC address."""
        results = []
        config = get_config()

        # Get gateway ARP entries from last hour
        recent_time = datetime.utcnow() - timedelta(hours=1)
        gateway_entries = (
            self.db.query(ARPEntry)
            .filter(
                and_(
                    ARPEntry.ip_address == gateway_ip,
                    ARPEntry.seen_at > recent_time,
                )
            )
            .order_by(ARPEntry.seen_at.asc())
            .all()
        )

        if len(gateway_entries) < 2:
            return results

        # Check for MAC changes
        macs_seen = set(e.mac_address for e in gateway_entries)

        if len(macs_seen) > 1:
            # Gateway MAC changed - critical alert
            expected_mac = config.detection.gateway_mac

            evidence = {
                "gateway_ip": gateway_ip,
                "mac_addresses": list(macs_seen),
                "expected_mac": expected_mac,
                "change_times": [e.seen_at.isoformat() for e in gateway_entries],
            }

            severity = (
                AlertSeverity.CRITICAL
                if expected_mac and expected_mac not in macs_seen
                else AlertSeverity.HIGH
            )

            results.append(
                DetectionResult(
                    alert_type=AlertType.ARP_SPOOF,
                    severity=severity,
                    title=f"Gateway MAC Address Changed: {gateway_ip}",
                    description=f"Gateway at {gateway_ip} changed MAC address. "
                    f"This is highly suspicious and indicates possible MITM attack. "
                    f"MACs seen: {', '.join(macs_seen)}",
                    evidence=evidence,
                    score=95,
                )
            )

        return results

    def _detect_arp_anomalies(self) -> List[DetectionResult]:
        """Detect unusual ARP activity patterns."""
        results = []

        # Check for excessive ARP replies
        window_start = datetime.utcnow() - timedelta(minutes=5)

        # Group by MAC to find devices sending many ARP replies
        arp_entries = (
            self.db.query(ARPEntry)
            .filter(
                and_(
                    ARPEntry.operation == "reply",
                    ARPEntry.seen_at > window_start,
                )
            )
            .all()
        )

        mac_reply_count: Dict[str, int] = defaultdict(int)
        mac_ips: Dict[str, set] = defaultdict(set)

        for entry in arp_entries:
            mac_reply_count[entry.mac_address] += 1
            mac_ips[entry.mac_address].add(entry.ip_address)

        # Flag devices with excessive replies
        for mac, count in mac_reply_count.items():
            if count > 50:  # More than 50 ARP replies in 5 minutes
                evidence = {
                    "mac_address": mac,
                    "arp_reply_count": count,
                    "window_minutes": 5,
                    "ip_addresses_claimed": list(mac_ips[mac]),
                }

                results.append(
                    DetectionResult(
                        alert_type=AlertType.ARP_SPOOF,
                        severity=AlertSeverity.HIGH,
                        title=f"Excessive ARP Replies from {mac}",
                        description=f"Device {mac} sent {count} ARP replies in 5 minutes, "
                        f"claiming {len(mac_ips[mac])} different IP addresses. "
                        f"This may indicate ARP poisoning attack.",
                        evidence=evidence,
                        score=80,
                    )
                )

        return results
