"""Security Alert management service."""

from typing import Optional, List
from sqlalchemy.orm import Session
from app.models.alert import SecurityAlert


class AlertService:
    @staticmethod
    def create_alert(
        db: Session,
        alert_type: str,
        severity: str,
        source_ip: str,
        description: str,
        user_id: Optional[int] = None,
        status: str = "OPEN"
    ) -> SecurityAlert:
        """Create and persist a new security alert."""
        alert = SecurityAlert(
            alert_type=alert_type,
            severity=severity,
            source_ip=source_ip,
            description=description,
            user_id=user_id,
            status=status
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def update_status(db: Session, alert_id: int, new_status: str) -> Optional[SecurityAlert]:
        """Update the triage status of an existing alert."""
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if alert:
            alert.status = new_status
            db.commit()
            db.refresh(alert)
        return alert

    @staticmethod
    def get_alerts(
        db: Session,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        user_id: Optional[int] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[SecurityAlert]:
        """Query alerts with optional status, severity, and pagination filters."""
        query = db.query(SecurityAlert)
        if status:
            query = query.filter(SecurityAlert.status == status)
        if severity:
            query = query.filter(SecurityAlert.severity == severity)
        if user_id:
            query = query.filter(SecurityAlert.user_id == user_id)
        return query.order_by(SecurityAlert.timestamp.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_alert_by_id(db: Session, alert_id: int) -> Optional[SecurityAlert]:
        """Fetch alert by ID."""
        return db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
