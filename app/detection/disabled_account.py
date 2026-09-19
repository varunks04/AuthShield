"""Rule 4: Disabled Account Authentication Attempt Detection."""

from typing import Optional
from sqlalchemy.orm import Session
from app.models.alert import SecurityAlert
from app.services.alert_service import AlertService


def check_disabled_account_attempt(
    db: Session,
    user_id: int,
    username: str,
    ip_address: str
) -> SecurityAlert:
    """
    Triggers a security alert whenever an authentication attempt targets a disabled account.
    """
    alert = AlertService.create_alert(
        db=db,
        alert_type="LOGIN_ATTEMPT_DISABLED_ACCOUNT",
        severity="HIGH",
        source_ip=ip_address,
        user_id=user_id,
        description=(
            f"Disabled account login attempt: Account '{username}' (ID: {user_id}) "
            f"is currently disabled but received an authentication request from IP {ip_address}."
        )
    )
    return alert
