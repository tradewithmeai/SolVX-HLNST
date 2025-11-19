"""Base detection engine framework."""

from abc import ABC, abstractmethod
from typing import List, Optional
from datetime import datetime

from sqlalchemy.orm import Session

from solvx_net.core.models import Alert, AlertType, AlertSeverity, AlertStatus, Device
from solvx_net.core.logging import get_logger

logger = get_logger(__name__)


class DetectionResult:
    """Result from a detection engine."""

    def __init__(
        self,
        alert_type: AlertType,
        severity: AlertSeverity,
        title: str,
        description: str,
        device_id: Optional[int] = None,
        evidence: dict = None,
        score: int = 0,
    ):
        """
        Initialize detection result.

        Args:
            alert_type: Type of alert
            severity: Severity level
            title: Alert title
            description: Detailed description
            device_id: Associated device ID (optional)
            evidence: Evidence dictionary
            score: Threat score (0-100)
        """
        self.alert_type = alert_type
        self.severity = severity
        self.title = title
        self.description = description
        self.device_id = device_id
        self.evidence = evidence or {}
        self.score = score

    def to_alert_model(self) -> Alert:
        """Convert to Alert model."""
        return Alert(
            device_id=self.device_id,
            alert_type=self.alert_type,
            severity=self.severity,
            title=self.title,
            description=self.description,
            evidence=self.evidence,
            score=self.score,
            status=AlertStatus.OPEN,
        )


class BaseDetector(ABC):
    """Base class for all detection engines."""

    def __init__(self, db: Session):
        """
        Initialize detector.

        Args:
            db: Database session
        """
        self.db = db
        self.logger = get_logger(self.__class__.__name__)

    @property
    @abstractmethod
    def name(self) -> str:
        """Detector name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Detector description."""
        pass

    @abstractmethod
    def detect(self) -> List[DetectionResult]:
        """
        Run detection logic.

        Returns:
            List of detection results
        """
        pass

    def run(self) -> List[Alert]:
        """
        Run detector and save alerts.

        Returns:
            List of created alerts
        """
        self.logger.info(f"Running detector: {self.name}")

        try:
            # Run detection logic
            results = self.detect()
            self.logger.info(f"Detector {self.name} found {len(results)} issues")

            # Convert to alerts and save
            alerts = []
            for result in results:
                alert = result.to_alert_model()
                self.db.add(alert)
                alerts.append(alert)

            self.db.flush()

            return alerts

        except Exception as e:
            self.logger.error(f"Detector {self.name} failed: {e}", exc_info=True)
            raise


class DetectionEngine:
    """Main detection engine that runs all detectors."""

    def __init__(self, db: Session):
        """
        Initialize detection engine.

        Args:
            db: Database session
        """
        self.db = db
        self.detectors: List[BaseDetector] = []
        self.logger = get_logger(__name__)

    def register_detector(self, detector: BaseDetector):
        """
        Register a detector.

        Args:
            detector: Detector instance
        """
        self.detectors.append(detector)
        self.logger.info(f"Registered detector: {detector.name}")

    def run_all(self) -> List[Alert]:
        """
        Run all registered detectors.

        Returns:
            List of all alerts created
        """
        self.logger.info(f"Running {len(self.detectors)} detectors...")

        all_alerts = []
        for detector in self.detectors:
            try:
                alerts = detector.run()
                all_alerts.extend(alerts)
            except Exception as e:
                self.logger.error(f"Detector {detector.name} failed: {e}")

        self.db.commit()
        self.logger.info(f"Detection complete: {len(all_alerts)} alerts created")

        return all_alerts

    def run_detector_by_name(self, name: str) -> List[Alert]:
        """
        Run specific detector by name.

        Args:
            name: Detector name

        Returns:
            List of alerts created
        """
        for detector in self.detectors:
            if detector.name.lower() == name.lower():
                alerts = detector.run()
                self.db.commit()
                return alerts

        raise ValueError(f"Detector not found: {name}")
