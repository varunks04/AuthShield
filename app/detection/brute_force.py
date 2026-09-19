"""Rule 1: Brute-Force Login Detection."""

from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.config import settings
from app.models.audit import AuditLog
from app.models.alert import SecurityAlert
from app.services.alert_service import AlertService


def check_brute_force(
    db: Session,
    ip_address: str,
    user_id: Optional[int] = None
) -> Optional[SecurityAlert]:
    """
    Evaluates whether the number of failed logins from this IP within the configured
    time window meets or exceeds the brute force threshold.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.BRUTE_FORCE_WINDOW_SECONDS)

    failed_count = (
        db.query(func.count(AuditLog.id))
        .filter(
            AuditLog.ip_address == ip_address,
            AuditLog.action == "LOGIN_FAILED",
            AuditLog.timestamp >= cutoff
        )
        .scalar()
    ) or 0

    if failed_count >= settings.BRUTE_FORCE_THRESHOLD:
        # Check if an alert was already triggered for this IP within the window to prevent alert flooding
        existing_alert = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.source_ip == ip_address,
                SecurityAlert.alert_type == "BRUTE_FORCE_LOGIN",
                SecurityAlert.timestamp >= cutoff
            )
            .first()
        )
        if not existing_alert:
            alert = AlertService.create_alert(
                db=db,
                alert_type="BRUTE_FORCE_LOGIN",
                severity="HIGH",
                source_ip=ip_address,
                user_id=user_id,
                description=(
                    f"Brute-force attack detected: {failed_count} failed login attempts "
                    f"from IP {ip_address} within {settings.BRUTE_FORCE_WINDOW_SECONDS // 60} minutes."
                )
            )
            return alert
    return None
