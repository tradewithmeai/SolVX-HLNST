"""Flow aggregation and analysis."""

from typing import Dict, List, Tuple, Optional
from datetime import datetime
from collections import defaultdict

from solvx_net.pcap.parser import PacketInfo
from solvx_net.core.logging import get_logger
from solvx_net.core.models import Flow

logger = get_logger(__name__)


class FlowKey:
    """Flow identifier key."""

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: str,
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

    def __eq__(self, other):
        return (
            self.src_ip == other.src_ip
            and self.dst_ip == other.dst_ip
            and self.src_port == other.src_port
            and self.dst_port == other.dst_port
            and self.protocol == other.protocol
        )

    def __repr__(self):
        return f"<FlowKey {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} [{self.protocol}]>"


class FlowData:
    """Aggregated flow data."""

    def __init__(
        self,
        flow_key: FlowKey,
        first_packet: PacketInfo,
    ):
        self.flow_key = flow_key
        self.src_mac = first_packet.src_mac
        self.dst_mac = first_packet.dst_mac

        self.start_time = first_packet.timestamp
        self.end_time = first_packet.timestamp

        self.packet_count = 1
        self.byte_count = first_packet.size

        self.flags = set()
        if first_packet.flags:
            self.flags.update(first_packet.flags.split("|"))

        # Collect metadata from packets
        self.metadata = {
            "dns_queries": [],
            "arp_operations": [],
        }

        if "dns" in first_packet.metadata:
            dns_info = first_packet.metadata["dns"]
            if "queries" in dns_info:
                self.metadata["dns_queries"].extend(dns_info["queries"])

        if "arp" in first_packet.metadata:
            self.metadata["arp_operations"].append(first_packet.metadata["arp"])

    def add_packet(self, packet: PacketInfo):
        """Add packet to this flow."""
        self.packet_count += 1
        self.byte_count += packet.size

        # Update time range
        if packet.timestamp < self.start_time:
            self.start_time = packet.timestamp
        if packet.timestamp > self.end_time:
            self.end_time = packet.timestamp

        # Update flags
        if packet.flags:
            self.flags.update(packet.flags.split("|"))

        # Update metadata
        if "dns" in packet.metadata:
            dns_info = packet.metadata["dns"]
            if "queries" in dns_info:
                self.metadata["dns_queries"].extend(dns_info["queries"])

        if "arp" in packet.metadata:
            self.metadata["arp_operations"].append(packet.metadata["arp"])

    def to_flow_model(self, capture_id: int) -> Flow:
        """Convert to SQLAlchemy Flow model."""
        return Flow(
            capture_id=capture_id,
            src_ip=self.flow_key.src_ip,
            src_port=self.flow_key.src_port,
            src_mac=self.src_mac,
            dst_ip=self.flow_key.dst_ip,
            dst_port=self.flow_key.dst_port,
            dst_mac=self.dst_mac,
            protocol=self.flow_key.protocol,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            start_time=self.start_time,
            end_time=self.end_time,
            flags="|".join(sorted(self.flags)) if self.flags else None,
            extra_metadata=self.metadata,
        )

    def __repr__(self):
        return f"<FlowData {self.flow_key} packets={self.packet_count} bytes={self.byte_count}>"


class FlowBuilder:
    """Build flows from packets."""

    def __init__(self, timeout_seconds: int = 60):
        """
        Initialize flow builder.

        Args:
            timeout_seconds: Flow timeout (flows idle for this long are considered complete)
        """
        self.timeout_seconds = timeout_seconds
        self.flows: Dict[FlowKey, FlowData] = {}
        self.completed_flows: List[FlowData] = []

        logger.info(f"Initialized flow builder (timeout={timeout_seconds}s)")

    def add_packet(self, packet: PacketInfo):
        """
        Add packet to flow aggregation.

        Args:
            packet: Parsed packet information
        """
        # Skip packets without IP layer
        if not packet.src_ip or not packet.dst_ip:
            return

        # Create flow key
        flow_key = FlowKey(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol_name,
        )

        # Add to existing flow or create new one
        if flow_key in self.flows:
            self.flows[flow_key].add_packet(packet)
        else:
            self.flows[flow_key] = FlowData(flow_key, packet)

    def finalize(self) -> List[FlowData]:
        """
        Finalize all flows and return them.

        Returns:
            List of completed flows
        """
        all_flows = list(self.flows.values()) + self.completed_flows
        logger.info(f"Finalized {len(all_flows)} flows")
        return all_flows

    def get_flow_statistics(self) -> Dict:
        """
        Get statistics about current flows.

        Returns:
            Dictionary with flow statistics
        """
        all_flows = self.flows.values()

        if not all_flows:
            return {
                "total_flows": 0,
                "total_packets": 0,
                "total_bytes": 0,
            }

        total_packets = sum(f.packet_count for f in all_flows)
        total_bytes = sum(f.byte_count for f in all_flows)

        # Protocol breakdown
        protocol_stats = defaultdict(int)
        for flow in all_flows:
            protocol_stats[flow.flow_key.protocol] += 1

        return {
            "total_flows": len(all_flows),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocols": dict(protocol_stats),
        }


def build_flows_from_packets(
    packets: List[PacketInfo],
    timeout_seconds: int = 60,
) -> List[FlowData]:
    """
    Build flows from a list of packets.

    Args:
        packets: List of parsed packets
        timeout_seconds: Flow timeout in seconds

    Returns:
        List of flow data
    """
    builder = FlowBuilder(timeout_seconds=timeout_seconds)

    for packet in packets:
        builder.add_packet(packet)

    return builder.finalize()
