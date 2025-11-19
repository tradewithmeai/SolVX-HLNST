"""PCAP file parsing using Scapy."""

from pathlib import Path
from typing import Generator, Dict, Any, Optional
from datetime import datetime
from scapy.all import rdpcap, Packet, IP, IPv6, TCP, UDP, ICMP, ARP, Ether, DNS
from scapy.layers.inet import TCP as TCPLayer

from solvx_net.core.logging import get_logger

logger = get_logger(__name__)


class PacketInfo:
    """Structured packet information."""

    def __init__(self, packet: Packet, timestamp: float):
        self.timestamp = datetime.fromtimestamp(timestamp)
        self.raw_packet = packet

        # Ethernet layer
        if packet.haslayer(Ether):
            self.src_mac = packet[Ether].src
            self.dst_mac = packet[Ether].dst
        else:
            self.src_mac = None
            self.dst_mac = None

        # Network layer
        if packet.haslayer(IP):
            self.src_ip = packet[IP].src
            self.dst_ip = packet[IP].dst
            self.protocol = packet[IP].proto
            self.ip_version = 4
        elif packet.haslayer(IPv6):
            self.src_ip = packet[IPv6].src
            self.dst_ip = packet[IPv6].dst
            self.protocol = packet[IPv6].nh
            self.ip_version = 6
        else:
            self.src_ip = None
            self.dst_ip = None
            self.protocol = None
            self.ip_version = None

        # Transport layer
        self.src_port = None
        self.dst_port = None
        self.protocol_name = "UNKNOWN"
        self.flags = None

        if packet.haslayer(TCP):
            self.src_port = packet[TCP].sport
            self.dst_port = packet[TCP].dport
            self.protocol_name = "TCP"
            # TCP flags
            self.flags = self._get_tcp_flags(packet[TCP])
        elif packet.haslayer(UDP):
            self.src_port = packet[UDP].sport
            self.dst_port = packet[UDP].dport
            self.protocol_name = "UDP"
        elif packet.haslayer(ICMP):
            self.protocol_name = "ICMP"
        elif packet.haslayer(ARP):
            self.protocol_name = "ARP"

        # Packet size
        self.size = len(packet)

        # Additional metadata
        self.metadata = {}

        # DNS info
        if packet.haslayer(DNS):
            self.metadata["dns"] = self._extract_dns_info(packet[DNS])

        # ARP info
        if packet.haslayer(ARP):
            self.metadata["arp"] = self._extract_arp_info(packet[ARP])

    def _get_tcp_flags(self, tcp_layer) -> str:
        """Extract TCP flags as string."""
        flags = []
        if tcp_layer.flags.F:
            flags.append("FIN")
        if tcp_layer.flags.S:
            flags.append("SYN")
        if tcp_layer.flags.R:
            flags.append("RST")
        if tcp_layer.flags.P:
            flags.append("PSH")
        if tcp_layer.flags.A:
            flags.append("ACK")
        if tcp_layer.flags.U:
            flags.append("URG")
        return "|".join(flags) if flags else ""

    def _extract_dns_info(self, dns_layer) -> Dict[str, Any]:
        """Extract DNS query/response information."""
        info = {
            "qr": dns_layer.qr,  # 0=query, 1=response
            "qd_count": dns_layer.qdcount,
            "an_count": dns_layer.ancount,
        }

        # Extract query names
        if hasattr(dns_layer, "qd") and dns_layer.qd:
            info["queries"] = []
            query = dns_layer.qd
            while query:
                if hasattr(query, "qname"):
                    info["queries"].append(query.qname.decode() if isinstance(query.qname, bytes) else str(query.qname))
                query = query.payload if hasattr(query, "payload") else None

        return info

    def _extract_arp_info(self, arp_layer) -> Dict[str, Any]:
        """Extract ARP request/reply information."""
        return {
            "op": "request" if arp_layer.op == 1 else "reply",
            "hwsrc": arp_layer.hwsrc,
            "psrc": arp_layer.psrc,
            "hwdst": arp_layer.hwdst,
            "pdst": arp_layer.pdst,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "protocol": self.protocol_name,
            "size": self.size,
            "flags": self.flags,
            "metadata": self.metadata,
        }

    def __repr__(self):
        return f"<Packet {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} [{self.protocol_name}]>"


class PCAPParser:
    """PCAP file parser."""

    def __init__(self, pcap_path: Path):
        """
        Initialize parser.

        Args:
            pcap_path: Path to PCAP file
        """
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        logger.info(f"Initialized PCAP parser for {pcap_path}")

    def parse(self, limit: Optional[int] = None) -> Generator[PacketInfo, None, None]:
        """
        Parse PCAP file and yield packet information.

        Args:
            limit: Maximum number of packets to parse (None = all)

        Yields:
            PacketInfo objects
        """
        logger.info(f"Parsing PCAP file: {self.pcap_path}")

        try:
            # Read PCAP file
            packets = rdpcap(str(self.pcap_path))
            logger.info(f"Loaded {len(packets)} packets from PCAP")

            count = 0
            for packet in packets:
                if limit and count >= limit:
                    break

                try:
                    # Extract timestamp
                    timestamp = float(packet.time)
                    packet_info = PacketInfo(packet, timestamp)
                    yield packet_info
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to parse packet: {e}")
                    continue

            logger.info(f"Successfully parsed {count} packets")

        except Exception as e:
            logger.error(f"Failed to read PCAP file: {e}")
            raise

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics about the PCAP file.

        Returns:
            Dictionary with summary information
        """
        packets = list(self.parse())

        if not packets:
            return {
                "packet_count": 0,
                "start_time": None,
                "end_time": None,
                "duration_seconds": 0,
            }

        start_time = min(p.timestamp for p in packets)
        end_time = max(p.timestamp for p in packets)
        duration = (end_time - start_time).total_seconds()

        protocols = {}
        for p in packets:
            protocols[p.protocol_name] = protocols.get(p.protocol_name, 0) + 1

        return {
            "packet_count": len(packets),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": duration,
            "protocols": protocols,
            "file_path": str(self.pcap_path),
            "file_size_bytes": self.pcap_path.stat().st_size,
        }
