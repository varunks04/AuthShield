"""Rule 2: Repeated Unauthorized Access Detection."""

from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.config import settings
from app.models.audit import AuditLog
from app.models.alert import SecurityAlert
from app.services.alert_service import AlertService


def check_unauthorized_access(
    db: Session,
    ip_address: str,
    user_id: Optional[int] = None
) -> Optional[SecurityAlert]:
    """
    Evaluates whether repeated ACCESS_DENIED events have occurred within
    the configured time window from the same IP or user.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.UNAUTHORIZED_ACCESS_WINDOW_SECONDS)

    query = db.query(func.count(AuditLog.id)).filter(
        AuditLog.action == "ACCESS_DENIED",
        AuditLog.timestamp >= cutoff
    )

    if user_id:
        query = query.filter((AuditLog.user_id == user_id) | (AuditLog.ip_address == ip_address))
    else:
        query = query.filter(AuditLog.ip_address == ip_address)

    denied_count = query.scalar() or 0

    if denied_count >= settings.UNAUTHORIZED_ACCESS_THRESHOLD:
        existing_alert = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.source_ip == ip_address,
                SecurityAlert.alert_type == "REPEATED_UNAUTHORIZED_ACCESS",
                SecurityAlert.timestamp >= cutoff
            )
            .first()
        )
        if not existing_alert:
            user_label = f"User ID {user_id}" if user_id else "Unauthenticated client"
            alert = AlertService.create_alert(
                db=db,
                alert_type="REPEATED_UNAUTHORIZED_ACCESS",
                severity="MEDIUM",
                source_ip=ip_address,
                user_id=user_id,
                description=(
                    f"Repeated unauthorized access attempts detected: {denied_count} "
                    f"ACCESS_DENIED events from {user_label} at IP {ip_address}."
                )
            )
            return alert
    return None
