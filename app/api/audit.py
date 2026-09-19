"""Audit API endpoints for security event inspection."""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLogResponse
from app.auth.permissions import require_roles

router = APIRouter(prefix="/audit-logs", tags=["Audit Logging"])


@router.get("", response_model=List[AuditLogResponse])
def get_audit_logs(
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    ip_address: Optional[str] = Query(None, description="Filter by IP address"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    status: Optional[str] = Query(None, description="Filter by status: SUCCESS, FAILURE, DENIED"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db)
):
    """
    Retrieve security audit logs with filtering options.
    Restricted to Analyst and Administrator roles.
    """
    query = db.query(AuditLog)

    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)
    if ip_address:
        query = query.filter(AuditLog.ip_address.ilike(f"%{ip_address}%"))
    if action:
        query = query.filter(AuditLog.action == action)
    if status:
        query = query.filter(AuditLog.status == status)

    logs = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
    return logs
