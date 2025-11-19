"""PCAP import functionality."""

from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from solvx_net.core.database import get_db
from solvx_net.core.models import Capture, CaptureType, Flow
from solvx_net.core.logging import get_logger
from solvx_net.pcap.parser import PCAPParser
from solvx_net.analysis.flows import build_flows_from_packets
from solvx_net.fingerprinting.resolver import DeviceResolver
from solvx_net.fingerprinting.fingerprinter import DeviceFingerprinter

logger = get_logger(__name__)


class PCAPImporter:
    """Import PCAP files into database."""

    def __init__(self, pcap_path: Path):
        """
        Initialize importer.

        Args:
            pcap_path: Path to PCAP file
        """
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        self.parser = PCAPParser(self.pcap_path)
        logger.info(f"Initialized PCAP importer for {pcap_path}")

    def import_pcap(
        self,
        notes: Optional[str] = None,
        batch_size: int = 1000,
    ) -> Dict[str, Any]:
        """
        Import PCAP file into database.

        Args:
            notes: Optional notes about this capture
            batch_size: Number of flows to batch insert at once

        Returns:
            Dictionary with import statistics
        """
        logger.info(f"Starting PCAP import: {self.pcap_path}")

        with get_db() as db:
            # Parse all packets
            logger.info("Parsing packets...")
            packets = list(self.parser.parse())
            logger.info(f"Parsed {len(packets)} packets")

            if not packets:
                logger.warning("No packets found in PCAP file")
                return {
                    "success": False,
                    "error": "No packets found in PCAP file",
                }

            # Determine time range
            timestamps = [p.timestamp for p in packets]
            start_time = min(timestamps)
            end_time = max(timestamps)

            # Create capture record
            capture = Capture(
                type=CaptureType.OFFLINE_PCAP,
                source=str(self.pcap_path),
                start_time=start_time,
                end_time=end_time,
                num_packets=len(packets),
                notes=notes,
                extra_metadata={
                    "file_size_bytes": self.pcap_path.stat().st_size,
                    "import_time": datetime.utcnow().isoformat(),
                },
            )

            db.add(capture)
            db.flush()  # Get capture ID

            logger.info(f"Created capture record (ID={capture.id})")

            # Build flows
            logger.info("Building flows from packets...")
            flow_data_list = build_flows_from_packets(packets)
            logger.info(f"Built {len(flow_data_list)} flows")

            # Convert to Flow models and insert in batches
            logger.info("Inserting flows into database...")
            flows = []
            for flow_data in flow_data_list:
                flow = flow_data.to_flow_model(capture.id)
                flows.append(flow)

                if len(flows) >= batch_size:
                    db.bulk_save_objects(flows)
                    db.flush()
                    flows = []

            # Insert remaining flows
            if flows:
                db.bulk_save_objects(flows)

            # Update capture with flow count
            capture.num_flows = len(flow_data_list)
            db.flush()

            # Resolve devices from flows
            logger.info("Resolving devices from flows...")
            resolver = DeviceResolver(db)
            all_flows = db.query(Flow).filter(Flow.capture_id == capture.id).all()
            devices_resolved = resolver.resolve_flows_batch(all_flows)
            logger.info(f"Resolved {devices_resolved} device associations")

            # Fingerprint newly discovered devices
            logger.info("Fingerprinting devices...")
            fingerprinter = DeviceFingerprinter(db)
            fingerprint_results = fingerprinter.fingerprint_all_devices()
            logger.info(f"Fingerprinted {len(fingerprint_results)} devices")

            db.commit()

            logger.info(
                f"Successfully imported PCAP: {len(packets)} packets, "
                f"{len(flow_data_list)} flows, {devices_resolved} devices"
            )

            return {
                "success": True,
                "capture_id": capture.id,
                "num_packets": len(packets),
                "num_flows": len(flow_data_list),
                "num_devices": devices_resolved,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": (end_time - start_time).total_seconds(),
            }


def import_pcap_file(
    pcap_path: Path,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience function to import a PCAP file.

    Args:
        pcap_path: Path to PCAP file
        notes: Optional notes

    Returns:
        Import statistics
    """
    importer = PCAPImporter(pcap_path)
    return importer.import_pcap(notes=notes)
