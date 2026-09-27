"""Remediation & Active Threat Containment API Endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.user import User
from app.auth.permissions import require_roles, get_client_ip, get_current_user
from app.services.blocklist_service import BlocklistService
from app.services.audit_service import AuditService

router = APIRouter(prefix="/remediation", tags=["Remediation & Active Defense"])


class BlockIPRequest(BaseModel):
    ip_address: str = Field(..., description="IP address to block")
    reason: Optional[str] = Field("Manually quarantined by security analyst", description="Justification for blocking")


class UnblockIPRequest(BaseModel):
    ip_address: str = Field(..., description="IP address to unblock")


class BlockedIPResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    reason: Optional[str]
    blocked_by: str
    is_active: bool
    timestamp: str


@router.get("/blocked-ips")
def list_blocked_ips(
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db)
):
    """Retrieve all actively blocked IP addresses."""
    entries = BlocklistService.get_all_blocked(db)
    return [
        {
            "id": e.id,
            "ip_address": e.ip_address,
            "reason": e.reason,
            "blocked_by": e.blocked_by,
            "is_active": e.is_active,
            "timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else ""
        }
        for e in entries
    ]


@router.post("/block-ip")
def block_ip_address(
    payload: BlockIPRequest,
    request: Request,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db)
):
    """Manually blocks a source IP address, denying all subsequent requests."""
    blocked = BlocklistService.block_ip(
        db=db,
        ip_address=payload.ip_address,
        reason=payload.reason,
        blocked_by=current_user.email
    )
    return {
        "status": "success",
        "message": f"IP address '{blocked.ip_address}' is now actively quarantined.",
        "ip_address": blocked.ip_address,
        "reason": blocked.reason
    }


@router.post("/unblock-ip")
def unblock_ip_address(
    payload: UnblockIPRequest,
    request: Request,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db)
):
    """Releases an IP address from the active denylist."""
    success = BlocklistService.unblock_ip(
        db=db,
        ip_address=payload.ip_address,
        unblocked_by=current_user.email
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP address '{payload.ip_address}' was not found on active blocklist"
        )
    return {
        "status": "success",
        "message": f"IP address '{payload.ip_address}' has been released from the blocklist."
    }


@router.post("/quarantine-user/{user_id}")
def quarantine_user_account(
    user_id: int,
    request: Request,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db)
):
    """Immediately disables and quarantines a compromised user account."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    target_user.status = "disabled"
    db.commit()

    AuditService.log_event(
        db=db,
        action="USER_QUARANTINED",
        endpoint=f"/remediation/quarantine-user/{user_id}",
        status="SUCCESS",
        ip_address=get_client_ip(request),
        user_id=current_user.id,
        details=f"Account '{target_user.username}' (ID: {target_user.id}) quarantined by {current_user.email}"
    )

    return {
        "status": "success",
        "message": f"User account '{target_user.username}' has been quarantined and disabled.",
        "user_id": target_user.id,
        "new_status": "disabled"
    }


@router.post("/restore-user/{user_id}")
def restore_user_account(
    user_id: int,
    request: Request,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db)
):
    """Restores and re-enables a quarantined user account."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    target_user.status = "active"
    db.commit()

    AuditService.log_event(
        db=db,
        action="USER_RESTORED",
        endpoint=f"/remediation/restore-user/{user_id}",
        status="SUCCESS",
        ip_address=get_client_ip(request),
        user_id=current_user.id,
        details=f"Account '{target_user.username}' (ID: {target_user.id}) restored by {current_user.email}"
    )

    return {
        "status": "success",
        "message": f"User account '{target_user.username}' has been restored and activated.",
        "user_id": target_user.id,
        "new_status": "active"
    }
