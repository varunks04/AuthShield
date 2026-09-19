"""Security Alerts API endpoints for alert triage and monitoring."""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database.connection import get_db
from app.models.alert import SecurityAlert
from app.models.user import User
from app.schemas.alert import SecurityAlertResponse, AlertStatusUpdateRequest
from app.auth.permissions import require_roles, get_client_ip
from app.services.alert_service import AlertService
from app.services.audit_service import AuditService

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


@router.get("", response_model=List[SecurityAlertResponse])
def get_alerts(
    status: Optional[str] = Query(None, description="Filter by status (OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE)"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db)
):
    """
    Retrieve security alerts. Restricted to Security Analyst and Administrator roles.
    """
    return AlertService.get_alerts(
        db=db,
        status=status,
        severity=severity,
        user_id=user_id,
        limit=limit,
        offset=offset
    )


@router.get("/summary/stats")
def get_alert_stats(
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Returns high-level alert statistics for analysts and security dashboards.
    """
    total_alerts = db.query(func.count(SecurityAlert.id)).scalar() or 0
    open_alerts = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "OPEN").scalar() or 0
    investigating = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "INVESTIGATING").scalar() or 0
    resolved = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "RESOLVED").scalar() or 0
    false_positives = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "FALSE_POSITIVE").scalar() or 0

    severity_counts = (
        db.query(SecurityAlert.severity, func.count(SecurityAlert.id))
        .group_by(SecurityAlert.severity)
        .all()
    )
    severity_breakdown = {sev: count for sev, count in severity_counts}

    return {
        "total": total_alerts,
        "open": open_alerts,
        "investigating": investigating,
        "resolved": resolved,
        "false_positive": false_positives,
        "by_severity": severity_breakdown
    }


@router.get("/{alert_id}", response_model=SecurityAlertResponse)
def get_alert_detail(
    alert_id: int,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db)
):
    """Retrieve detailed information for a specific security alert."""
    alert = AlertService.get_alert_by_id(db, alert_id=alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert {alert_id} not found"
        )
    return alert


@router.patch("/{alert_id}/status", response_model=SecurityAlertResponse)
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdateRequest,
    request: Request,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db)
):
    """
    Update alert triage lifecycle status (OPEN -> INVESTIGATING -> RESOLVED / FALSE_POSITIVE).
    """
    ip_address = get_client_ip(request)
    endpoint = request.url.path

    alert = AlertService.get_alert_by_id(db, alert_id=alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert {alert_id} not found"
        )

    old_status = alert.status
    alert.status = payload.status
    db.commit()
    db.refresh(alert)

    AuditService.log_event(
        db=db,
        action="ALERT_STATUS_UPDATED",
        endpoint=endpoint,
        status="SUCCESS",
        ip_address=ip_address,
        user_id=current_user.id,
        details=(
            f"Alert #{alert.id} ({alert.alert_type}) status changed from '{old_status}' "
            f"to '{payload.status}' by user '{current_user.username}'"
        )
    )

    return alert
