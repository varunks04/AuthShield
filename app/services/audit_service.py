"""Audit logging service."""

from typing import Optional
from sqlalchemy.orm import Session
from app.models.audit import AuditLog


class AuditService:
    @staticmethod
    def log_event(
        db: Session,
        action: str,
        endpoint: str,
        status: str,
        ip_address: str,
        user_id: Optional[int] = None,
        details: Optional[str] = None
    ) -> AuditLog:
        """Create and commit an audit log entry."""
        audit_entry = AuditLog(
            action=action,
            endpoint=endpoint,
            status=status,
            ip_address=ip_address,
            user_id=user_id,
            details=details,
        )
        db.add(audit_entry)
        db.commit()
        db.refresh(audit_entry)
        return audit_entry
