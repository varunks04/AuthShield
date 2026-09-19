"""Rule 3: Privilege Escalation Detection."""

from typing import Optional
from sqlalchemy.orm import Session
from app.models.alert import SecurityAlert
from app.services.alert_service import AlertService


def check_privilege_escalation(
    db: Session,
    target_user_id: int,
    target_username: str,
    old_role: str,
    new_role: str,
    admin_id: int,
    admin_ip: str
) -> Optional[SecurityAlert]:
    """
    Triggers a security alert whenever a user's role is elevated to admin,
    or changed to a higher privilege level.
    """
    if new_role == "admin" and old_role != "admin":
        alert = AlertService.create_alert(
            db=db,
            alert_type="PRIVILEGE_CHANGE",
            severity="HIGH",
            source_ip=admin_ip,
            user_id=target_user_id,
            description=(
                f"Privilege escalation: User '{target_username}' (ID: {target_user_id}) was promoted "
                f"from '{old_role}' to '{new_role}' by Admin (ID: {admin_id})."
            )
        )
        return alert
    return None
