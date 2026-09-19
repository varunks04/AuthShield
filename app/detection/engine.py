"""Unified Detection Engine for AuthShield."""

from typing import Optional
from sqlalchemy.orm import Session
from app.models.alert import SecurityAlert
from app.detection.brute_force import check_brute_force
from app.detection.unauthorized_access import check_unauthorized_access
from app.detection.privilege_change import check_privilege_escalation
from app.detection.disabled_account import check_disabled_account_attempt


class DetectionEngine:
    @staticmethod
    def on_login_failed(db: Session, ip_address: str, user_id: Optional[int] = None) -> Optional[SecurityAlert]:
        """Triggered upon failed login attempt."""
        return check_brute_force(db, ip_address=ip_address, user_id=user_id)

    @staticmethod
    def on_access_denied(db: Session, ip_address: str, user_id: Optional[int] = None) -> Optional[SecurityAlert]:
        """Triggered upon 403 / unauthorized access attempt."""
        return check_unauthorized_access(db, ip_address=ip_address, user_id=user_id)

    @staticmethod
    def on_role_changed(
        db: Session,
        target_user_id: int,
        target_username: str,
        old_role: str,
        new_role: str,
        admin_id: int,
        admin_ip: str
    ) -> Optional[SecurityAlert]:
        """Triggered upon administrative role change."""
        return check_privilege_escalation(
            db,
            target_user_id=target_user_id,
            target_username=target_username,
            old_role=old_role,
            new_role=new_role,
            admin_id=admin_id,
            admin_ip=admin_ip
        )

    @staticmethod
    def on_disabled_account_attempt(
        db: Session,
        user_id: int,
        username: str,
        ip_address: str
    ) -> SecurityAlert:
        """Triggered when disabled user tries to authenticate."""
        return check_disabled_account_attempt(
            db,
            user_id=user_id,
            username=username,
            ip_address=ip_address
        )
