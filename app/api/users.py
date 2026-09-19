"""Users API endpoints for profile management and administration."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session, joinedload
from app.database.connection import get_db
from app.models.user import User
from app.models.role import Role
from app.schemas.user import (
    UserResponse,
    UserProfileUpdateRequest,
    UserPasswordChangeRequest,
    UserRoleUpdateRequest,
    UserStatusUpdateRequest,
)
from app.auth.permissions import get_current_user, require_roles, get_client_ip
from app.auth.password import hash_password, verify_password
from app.services.audit_service import AuditService
from app.detection.engine import DetectionEngine

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Retrieve profile of currently authenticated user."""
    return current_user


@router.put("/me", response_model=UserResponse)
def update_current_user_profile(
    request: Request,
    payload: UserProfileUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update profile information for the authenticated user."""
    ip_address = get_client_ip(request)
    endpoint = request.url.path

    if payload.username and payload.username != current_user.username:
        if db.query(User).filter(User.username == payload.username).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username is already taken"
            )
        current_user.username = payload.username

    if payload.email and payload.email != current_user.email:
        if db.query(User).filter(User.email == payload.email).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is already taken"
            )
        current_user.email = payload.email

    db.commit()
    db.refresh(current_user)

    AuditService.log_event(
        db=db,
        action="USER_UPDATED",
        endpoint=endpoint,
        status="SUCCESS",
        ip_address=ip_address,
        user_id=current_user.id,
        details=f"User '{current_user.username}' updated profile details"
    )

    return current_user


@router.post("/me/password")
def change_user_password(
    request: Request,
    payload: UserPasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change the authenticated user's password."""
    ip_address = get_client_ip(request)
    endpoint = request.url.path

    if not verify_password(payload.current_password, current_user.password_hash):
        AuditService.log_event(
            db=db,
            action="PASSWORD_CHANGE_FAILED",
            endpoint=endpoint,
            status="FAILURE",
            ip_address=ip_address,
            user_id=current_user.id,
            details="Incorrect current password provided"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )

    current_user.password_hash = hash_password(payload.new_password)
    db.commit()

    AuditService.log_event(
        db=db,
        action="PASSWORD_CHANGED",
        endpoint=endpoint,
        status="SUCCESS",
        ip_address=ip_address,
        user_id=current_user.id,
        details=f"Password updated for user '{current_user.username}'"
    )

    return {"message": "Password changed successfully"}


@router.get("", response_model=List[UserResponse])
def list_users(
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db)
):
    """List system users. Accessible to Admin and Analyst roles."""
    users = (
        db.query(User)
        .options(joinedload(User.role))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return users


@router.patch("/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    payload: UserRoleUpdateRequest,
    request: Request,
    admin_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db)
):
    """
    Update a user's assigned role. Restricted strictly to Administrator role.
    Triggers privilege escalation detection if promoted to admin.
    """
    ip_address = get_client_ip(request)
    endpoint = request.url.path

    target_user = db.query(User).options(joinedload(User.role)).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found"
        )

    new_role = db.query(Role).filter(Role.name == payload.role_name).first()
    if not new_role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Role '{payload.role_name}' is not recognized"
        )

    old_role_name = target_user.role.name if target_user.role else "unknown"
    target_user.role_id = new_role.id
    target_user.role = new_role
    db.commit()
    db.refresh(target_user)

    AuditService.log_event(
        db=db,
        action="ROLE_CHANGED",
        endpoint=endpoint,
        status="SUCCESS",
        ip_address=ip_address,
        user_id=admin_user.id,
        details=(
            f"User '{target_user.username}' (ID: {target_user.id}) role changed "
            f"from '{old_role_name}' to '{new_role.name}' by admin '{admin_user.username}'"
        )
    )

    # Detection rule check for privilege escalation
    DetectionEngine.on_role_changed(
        db=db,
        target_user_id=target_user.id,
        target_username=target_user.username,
        old_role=old_role_name,
        new_role=new_role.name,
        admin_id=admin_user.id,
        admin_ip=ip_address
    )

    return target_user


@router.patch("/{user_id}/status", response_model=UserResponse)
def update_user_status(
    user_id: int,
    payload: UserStatusUpdateRequest,
    request: Request,
    admin_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db)
):
    """
    Enable or disable an account. Restricted strictly to Administrator role.
    """
    ip_address = get_client_ip(request)
    endpoint = request.url.path

    target_user = db.query(User).options(joinedload(User.role)).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found"
        )

    target_user.status = payload.status
    db.commit()
    db.refresh(target_user)

    action_label = "USER_DISABLED" if payload.status == "disabled" else "USER_ENABLED"
    AuditService.log_event(
        db=db,
        action=action_label,
        endpoint=endpoint,
        status="SUCCESS",
        ip_address=ip_address,
        user_id=admin_user.id,
        details=f"User '{target_user.username}' (ID: {target_user.id}) status set to '{payload.status}'"
    )

    return target_user
