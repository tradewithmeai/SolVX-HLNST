"""Threat scoring engine for devices and network."""

from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from sqlalchemy.orm import Session

from solvx_net.core.models import (
    Device,
    Alert,
    AlertStatus,
    AlertSeverity,
    ThreatScoreSnapshot,
)
from solvx_net.core.config import get_config
from solvx_net.core.logging import get_logger

logger = get_logger(__name__)


class ThreatScorer:
    """Calculate threat scores for devices and network."""

    def __init__(self, db: Session):
        """
        Initialize threat scorer.

        Args:
            db: Database session
        """
        self.db = db
        self.config = get_config()
        self.logger = get_logger(__name__)

    def score_device(self, device_id: int) -> Dict:
        """
        Calculate threat score for a specific device.

        Args:
            device_id: Device ID

        Returns:
            Dictionary with score and breakdown
        """
        device = self.db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise ValueError(f"Device not found: {device_id}")

        # Get recent alerts for this device
        window_hours = self.config.scoring.score_window_hours
        window_start = datetime.utcnow() - timedelta(hours=window_hours)

        alerts = (
            self.db.query(Alert)
            .filter(
                Alert.device_id == device_id,
                Alert.created_at > window_start,
                Alert.status == AlertStatus.OPEN,
            )
            .all()
        )

        # Calculate base score from alerts
        score_breakdown = defaultdict(float)
        total_score = 0.0

        for alert in alerts:
            # Get base weight for this alert type
            alert_weight = self.config.scoring.alert_weights.get(
                alert.alert_type.value, 50
            )

            # Apply severity multiplier
            severity_multiplier = {
                AlertSeverity.LOW: 0.5,
                AlertSeverity.MEDIUM: 1.0,
                AlertSeverity.HIGH: 1.5,
                AlertSeverity.CRITICAL: 2.0,
            }.get(alert.severity, 1.0)

            # Apply recency weight (more recent = higher weight)
            age_hours = (datetime.utcnow() - alert.created_at).total_seconds() / 3600
            recency_factor = max(0.5, 1.0 - (age_hours / window_hours) * 0.5)

            # Calculate weighted score
            weighted_score = alert_weight * severity_multiplier * recency_factor

            score_breakdown[alert.alert_type.value] += weighted_score
            total_score += weighted_score

        # Normalize to 0-100 scale
        # Cap at 100
        final_score = min(100.0, total_score)

        # Apply trust level adjustment
        from solvx_net.core.models import TrustLevel

        if device.trust_level == TrustLevel.BLOCKED:
            final_score = max(final_score, 80.0)  # Minimum 80 for blocked
        elif device.trust_level == TrustLevel.UNKNOWN:
            final_score += 10.0  # +10 penalty for unknown
        elif device.trust_level == TrustLevel.GUEST:
            final_score += 5.0  # +5 penalty for guest

        final_score = min(100.0, final_score)

        return {
            "device_id": device_id,
            "score": round(final_score, 2),
            "alert_count": len(alerts),
            "breakdown": dict(score_breakdown),
            "trust_level": device.trust_level.value,
            "risk_level": self._get_risk_level(final_score),
        }

    def score_all_devices(self) -> List[Dict]:
        """
        Score all devices in the database.

        Returns:
            List of device scores
        """
        devices = self.db.query(Device).all()
        scores = []

        for device in devices:
            try:
                score_data = self.score_device(device.id)
                scores.append(score_data)
            except Exception as e:
                self.logger.error(f"Failed to score device {device.id}: {e}")

        return scores

    def calculate_network_health(self) -> Dict:
        """
        Calculate overall network health score.

        Returns:
            Dictionary with network health metrics
        """
        # Get all device scores
        device_scores = self.score_all_devices()

        if not device_scores:
            return {
                "network_score": 0.0,
                "health_status": "unknown",
                "total_devices": 0,
                "high_risk_devices": 0,
                "medium_risk_devices": 0,
                "low_risk_devices": 0,
            }

        # Calculate average network score
        avg_score = sum(d["score"] for d in device_scores) / len(device_scores)

        # Count devices by risk level
        risk_counts = defaultdict(int)
        for score_data in device_scores:
            risk_counts[score_data["risk_level"]] += 1

        # Get alert statistics
        window_start = datetime.utcnow() - timedelta(hours=24)
        total_alerts = (
            self.db.query(Alert)
            .filter(Alert.created_at > window_start)
            .count()
        )

        open_critical_alerts = (
            self.db.query(Alert)
            .filter(
                Alert.status == AlertStatus.OPEN,
                Alert.severity == AlertSeverity.CRITICAL,
            )
            .count()
        )

        # Determine health status
        if avg_score < 20:
            health_status = "excellent"
        elif avg_score < 40:
            health_status = "good"
        elif avg_score < 60:
            health_status = "fair"
        elif avg_score < 80:
            health_status = "poor"
        else:
            health_status = "critical"

        return {
            "network_score": round(avg_score, 2),
            "health_status": health_status,
            "total_devices": len(device_scores),
            "high_risk_devices": risk_counts["high"],
            "medium_risk_devices": risk_counts["medium"],
            "low_risk_devices": risk_counts["low"],
            "safe_devices": risk_counts["safe"],
            "total_alerts_24h": total_alerts,
            "critical_open_alerts": open_critical_alerts,
        }

    def save_scores(self) -> int:
        """
        Calculate and save threat scores for all devices.

        Returns:
            Number of scores saved
        """
        scores = self.score_all_devices()
        timestamp = datetime.utcnow()

        for score_data in scores:
            snapshot = ThreatScoreSnapshot(
                device_id=score_data["device_id"],
                timestamp=timestamp,
                score=score_data["score"],
                details={
                    "breakdown": score_data["breakdown"],
                    "alert_count": score_data["alert_count"],
                    "risk_level": score_data["risk_level"],
                },
            )
            self.db.add(snapshot)

        # Save global network score
        network_health = self.calculate_network_health()
        global_snapshot = ThreatScoreSnapshot(
            device_id=None,  # Null for network-wide score
            timestamp=timestamp,
            score=network_health["network_score"],
            details=network_health,
        )
        self.db.add(global_snapshot)

        self.db.commit()

        self.logger.info(f"Saved threat scores for {len(scores)} devices")
        return len(scores)

    def get_score_history(
        self,
        device_id: Optional[int] = None,
        days: int = 7,
    ) -> List[Dict]:
        """
        Get historical threat scores.

        Args:
            device_id: Device ID (None for network-wide)
            days: Number of days of history

        Returns:
            List of score snapshots
        """
        start_time = datetime.utcnow() - timedelta(days=days)

        query = self.db.query(ThreatScoreSnapshot).filter(
            ThreatScoreSnapshot.timestamp > start_time
        )

        if device_id is not None:
            query = query.filter(ThreatScoreSnapshot.device_id == device_id)
        else:
            query = query.filter(ThreatScoreSnapshot.device_id.is_(None))

        snapshots = query.order_by(ThreatScoreSnapshot.timestamp.asc()).all()

        return [
            {
                "timestamp": s.timestamp.isoformat(),
                "score": s.score,
                "details": s.details,
            }
            for s in snapshots
        ]

    def _get_risk_level(self, score: float) -> str:
        """Get risk level label from score."""
        if score < 20:
            return "safe"
        elif score < 50:
            return "low"
        elif score < 75:
            return "medium"
        else:
            return "high"
