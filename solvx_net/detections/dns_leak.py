"""DNS leak detection engine."""

from typing import List, Set
from datetime import datetime, timedelta
from collections import defaultdict

from sqlalchemy.orm import Session

from solvx_net.core.models import Flow, Device, AlertType, AlertSeverity
from solvx_net.core.config import get_config
from solvx_net.detections.base import BaseDetector, DetectionResult


class DNSLeakDetector(BaseDetector):
    """Detect DNS leaks and unauthorized DNS queries."""

    # Well-known public DNS servers
    PUBLIC_DNS_SERVERS = {
        "8.8.8.8": "Google DNS",
        "8.8.4.4": "Google DNS",
        "1.1.1.1": "Cloudflare DNS",
        "1.0.0.1": "Cloudflare DNS",
        "9.9.9.9": "Quad9 DNS",
        "208.67.222.222": "OpenDNS",
        "208.67.220.220": "OpenDNS",
    }

    @property
    def name(self) -> str:
        return "DNS Leak Detector"

    @property
    def description(self) -> str:
        return "Detects DNS leaks and unauthorized DNS queries"

    def detect(self) -> List[DetectionResult]:
        """Run DNS leak detection."""
        results = []
        config = get_config()

        if not config.detection.enable_dns_leak_detection:
            return results

        # Get DNS flows from recent period
        recent_time = datetime.utcnow() - timedelta(hours=24)

        dns_flows = (
            self.db.query(Flow)
            .filter(
                Flow.dst_port == 53,  # DNS port
                Flow.protocol.in_(["UDP", "TCP"]),
                Flow.start_time > recent_time,
            )
            .all()
        )

        # Group by device
        device_dns_servers: dict[int, Set[str]] = defaultdict(set)

        for flow in dns_flows:
            if flow.src_device_id:
                device_dns_servers[flow.src_device_id].add(flow.dst_ip)

        # Check each device's DNS queries
        allowed_servers = set(config.detection.allowed_dns_servers)

        for device_id, dns_servers in device_dns_servers.items():
            # Check for unauthorized DNS servers
            unauthorized = dns_servers - allowed_servers

            if unauthorized:
                device = self.db.query(Device).filter(Device.id == device_id).first()
                if not device:
                    continue

                # Check if querying public DNS when not allowed
                public_dns_used = unauthorized & set(self.PUBLIC_DNS_SERVERS.keys())

                if public_dns_used and config.detection.flag_public_dns:
                    severity = AlertSeverity.MEDIUM
                    score = 60

                    public_names = [
                        f"{ip} ({self.PUBLIC_DNS_SERVERS[ip]})"
                        for ip in public_dns_used
                    ]

                    evidence = {
                        "device_id": device_id,
                        "mac_address": device.mac_address,
                        "unauthorized_dns_servers": list(public_dns_used),
                        "public_dns_names": public_names,
                        "allowed_servers": list(allowed_servers),
                        "query_count": len(
                            [f for f in dns_flows if f.src_device_id == device_id and f.dst_ip in public_dns_used]
                        ),
                    }

                    results.append(
                        DetectionResult(
                            alert_type=AlertType.DNS_LEAK,
                            severity=severity,
                            title=f"Public DNS Usage: {device.mac_address}",
                            description=f"Device {device.mac_address} ({device.vendor or 'Unknown'}) "
                            f"is using public DNS servers: {', '.join(public_names)}. "
                            f"This may indicate DNS leak or bypass of network DNS policy.",
                            device_id=device_id,
                            evidence=evidence,
                            score=score,
                        )
                    )

                # Check for completely unknown DNS servers
                unknown_dns = unauthorized - set(self.PUBLIC_DNS_SERVERS.keys())

                if unknown_dns:
                    severity = AlertSeverity.HIGH
                    score = 70

                    evidence = {
                        "device_id": device_id,
                        "mac_address": device.mac_address,
                        "unknown_dns_servers": list(unknown_dns),
                        "allowed_servers": list(allowed_servers),
                        "query_count": len(
                            [f for f in dns_flows if f.src_device_id == device_id and f.dst_ip in unknown_dns]
                        ),
                    }

                    results.append(
                        DetectionResult(
                            alert_type=AlertType.DNS_LEAK,
                            severity=severity,
                            title=f"Unauthorized DNS Server: {device.mac_address}",
                            description=f"Device {device.mac_address} ({device.vendor or 'Unknown'}) "
                            f"is querying unauthorized DNS servers: {', '.join(unknown_dns)}. "
                            f"This is a security concern and should be investigated.",
                            device_id=device_id,
                            evidence=evidence,
                            score=score,
                        )
                    )

        # Check for DNS tunneling indicators
        results.extend(self._detect_dns_tunneling(dns_flows))

        return results

    def _detect_dns_tunneling(self, dns_flows: List[Flow]) -> List[DetectionResult]:
        """Detect potential DNS tunneling."""
        results = []

        # Group by device and count queries
        device_query_count: dict[int, int] = defaultdict(int)

        for flow in dns_flows:
            if flow.src_device_id:
                device_query_count[flow.src_device_id] += flow.packet_count

        # Flag devices with excessive DNS queries
        for device_id, query_count in device_query_count.items():
            if query_count > 1000:  # More than 1000 DNS queries in 24h
                device = self.db.query(Device).filter(Device.id == device_id).first()
                if not device:
                    continue

                evidence = {
                    "device_id": device_id,
                    "mac_address": device.mac_address,
                    "dns_query_count": query_count,
                    "time_period_hours": 24,
                }

                results.append(
                    DetectionResult(
                        alert_type=AlertType.DNS_LEAK,
                        severity=AlertSeverity.MEDIUM,
                        title=f"Excessive DNS Queries: {device.mac_address}",
                        description=f"Device {device.mac_address} ({device.vendor or 'Unknown'}) "
                        f"made {query_count} DNS queries in 24 hours. "
                        f"This may indicate DNS tunneling or data exfiltration.",
                        device_id=device_id,
                        evidence=evidence,
                        score=65,
                    )
                )

        return results
