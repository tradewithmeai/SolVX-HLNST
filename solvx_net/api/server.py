"""FastAPI server for SolVX Network Security Toolkit."""

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
import math

from solvx_net import __version__
from solvx_net.core.database import get_db
from solvx_net.core.models import (
    Device as DeviceModel,
    Capture as CaptureModel,
    Flow as FlowModel,
    Alert as AlertModel,
    AlertStatus,
    AlertSeverity,
)
from solvx_net.api import schemas
from solvx_net.analysis.scoring import ThreatScorer
from solvx_net.detections.base import DetectionEngine
from solvx_net.detections.rogue_device import RogueDeviceDetector
from solvx_net.detections.arp_spoof import ARPSpoofDetector
from solvx_net.detections.dns_leak import DNSLeakDetector

app = FastAPI(
    title="SolVX Network Security Toolkit API",
    description="REST API for SolVX Home Lab Network & Security Toolkit",
    version=__version__,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    """API root endpoint."""
    return {
        "name": "SolVX Network Security Toolkit API",
        "version": __version__,
        "status": "running",
    }


@app.get("/stats", response_model=schemas.Statistics)
def get_statistics(db: Session = Depends(get_db)):
    """Get overall statistics."""
    total_devices = db.query(DeviceModel).count()
    total_captures = db.query(CaptureModel).count()
    total_flows = db.query(FlowModel).count()
    total_alerts = db.query(AlertModel).count()
    open_alerts = db.query(AlertModel).filter(AlertModel.status == AlertStatus.OPEN).count()
    critical_alerts = db.query(AlertModel).filter(
        AlertModel.severity == AlertSeverity.CRITICAL,
        AlertModel.status == AlertStatus.OPEN,
    ).count()

    return schemas.Statistics(
        total_devices=total_devices,
        total_captures=total_captures,
        total_flows=total_flows,
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
    )


# Device endpoints
@app.get("/devices", response_model=List[schemas.Device])
def list_devices(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    trust_level: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List all devices."""
    query = db.query(DeviceModel)

    if trust_level:
        query = query.filter(DeviceModel.trust_level == trust_level)

    devices = query.offset(skip).limit(limit).all()
    return devices


@app.get("/devices/{device_id}", response_model=schemas.Device)
def get_device(device_id: int, db: Session = Depends(get_db)):
    """Get device by ID."""
    device = db.query(DeviceModel).filter(DeviceModel.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


# Capture endpoints
@app.get("/captures", response_model=List[schemas.Capture])
def list_captures(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    """List all captures."""
    captures = db.query(CaptureModel).order_by(CaptureModel.created_at.desc()).offset(skip).limit(limit).all()
    return captures


@app.get("/captures/{capture_id}", response_model=schemas.Capture)
def get_capture(capture_id: int, db: Session = Depends(get_db)):
    """Get capture by ID."""
    capture = db.query(CaptureModel).filter(CaptureModel.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")
    return capture


# Flow endpoints
@app.get("/flows", response_model=List[schemas.Flow])
def list_flows(
    capture_id: Optional[int] = None,
    device_id: Optional[int] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    """List flows."""
    query = db.query(FlowModel)

    if capture_id:
        query = query.filter(FlowModel.capture_id == capture_id)
    if device_id:
        query = query.filter(
            (FlowModel.src_device_id == device_id) | (FlowModel.dst_device_id == device_id)
        )

    flows = query.offset(skip).limit(limit).all()
    return flows


# Alert endpoints
@app.get("/alerts", response_model=List[schemas.Alert])
def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    device_id: Optional[int] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    """List alerts."""
    query = db.query(AlertModel).order_by(AlertModel.created_at.desc())

    if status:
        query = query.filter(AlertModel.status == AlertStatus(status.lower()))
    if severity:
        query = query.filter(AlertModel.severity == AlertSeverity(severity.lower()))
    if device_id:
        query = query.filter(AlertModel.device_id == device_id)

    alerts = query.offset(skip).limit(limit).all()
    return alerts


@app.get("/alerts/{alert_id}", response_model=schemas.Alert)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Get alert by ID."""
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.patch("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)):
    """Acknowledge an alert."""
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = AlertStatus.ACKNOWLEDGED
    db.commit()

    return {"status": "acknowledged", "alert_id": alert_id}


@app.patch("/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    """Resolve an alert."""
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = AlertStatus.RESOLVED
    db.commit()

    return {"status": "resolved", "alert_id": alert_id}


# Threat scoring endpoints
@app.get("/threat-scores", response_model=List[schemas.ThreatScore])
def get_threat_scores(db: Session = Depends(get_db)):
    """Get threat scores for all devices."""
    scorer = ThreatScorer(db)
    scores = scorer.score_all_devices()
    return scores


@app.get("/threat-scores/{device_id}", response_model=schemas.ThreatScore)
def get_device_threat_score(device_id: int, db: Session = Depends(get_db)):
    """Get threat score for specific device."""
    scorer = ThreatScorer(db)
    try:
        score = scorer.score_device(device_id)
        return score
    except ValueError:
        raise HTTPException(status_code=404, detail="Device not found")


@app.get("/network-health", response_model=schemas.NetworkHealth)
def get_network_health(db: Session = Depends(get_db)):
    """Get overall network health."""
    scorer = ThreatScorer(db)
    health = scorer.calculate_network_health()
    return health


# Detection endpoints
@app.post("/detect/run")
def run_detection(detector: Optional[str] = None, db: Session = Depends(get_db)):
    """Run detection engines."""
    engine = DetectionEngine(db)
    engine.register_detector(RogueDeviceDetector(db))
    engine.register_detector(ARPSpoofDetector(db))
    engine.register_detector(DNSLeakDetector(db))

    if detector:
        alerts = engine.run_detector_by_name(detector)
    else:
        alerts = engine.run_all()

    return {
        "status": "completed",
        "alerts_created": len(alerts),
        "alert_ids": [a.id for a in alerts],
    }
