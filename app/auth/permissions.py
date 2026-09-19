"""Permissions and Role-Based Access Control (RBAC) dependency handlers."""

from typing import List, Optional, Callable
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session, joinedload
from app.database.connection import get_db
from app.models.user import User
from app.auth.jwt import decode_access_token
from app.services.audit_service import AuditService
from app.detection.engine import DetectionEngine

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


def get_client_ip(request: Request) -> str:
    """
    Extract client IP address. Supports X-Simulated-IP for automated attack simulation,
    X-Forwarded-For for proxy environments, and request.client.host.
    """
    simulated_ip = request.headers.get("x-simulated-ip")
    if simulated_ip:
        return simulated_ip.strip()

    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    if request.client and request.client.host:
        return request.client.host

    return "127.0.0.1"


def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Validates JWT token, extracts user identity, and verifies account active status.
    """
    ip_address = get_client_ip(request)
    endpoint = request.url.path

    if not token:
        # PRD FR-03: Missing token should be handled and logged
        AuditService.log_event(
            db=db,
            action="AUTHENTICATION_FAILED",
            endpoint=endpoint,
            status="FAILURE",
            ip_address=ip_address,
            details="Missing bearer authentication token"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing identity subject",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = int(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user identifier in token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).options(joinedload(User.role)).filter(User.id == user_id).first()
    if not user:
        AuditService.log_event(
            db=db,
            action="AUTHENTICATION_FAILED",
            endpoint=endpoint,
            status="FAILURE",
            ip_address=ip_address,
            user_id=user_id,
            details="Token contains non-existent user identifier"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.status != "active":
        AuditService.log_event(
            db=db,
            action="LOGIN_ATTEMPT_DISABLED_ACCOUNT",
            endpoint=endpoint,
            status="FAILURE",
            ip_address=ip_address,
            user_id=user.id,
            details=f"Disabled account '{user.username}' attempted to access protected endpoint"
        )
        DetectionEngine.on_disabled_account_attempt(
            db=db,
            user_id=user.id,
            username=user.username,
            ip_address=ip_address
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled. Please contact an administrator."
        )

    return user


def require_roles(*allowed_roles: str) -> Callable:
    """
    Factory creating a FastAPI dependency enforcing server-side Role-Based Access Control.
    Logs ACCESS_DENIED and evaluates repeated unauthorized access detection if unauthorized.
    """
    def role_checker(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ) -> User:
        user_role = current_user.role.name if current_user.role else "none"
        if user_role not in allowed_roles:
            ip_address = get_client_ip(request)
            endpoint = request.url.path

            AuditService.log_event(
                db=db,
                action="ACCESS_DENIED",
                endpoint=endpoint,
                status="DENIED",
                ip_address=ip_address,
                user_id=current_user.id,
                details=(
                    f"User '{current_user.username}' with role '{user_role}' denied access. "
                    f"Required roles: {list(allowed_roles)}"
                )
            )

            # Trigger detection engine check for repeated unauthorized access
            DetectionEngine.on_access_denied(
                db=db,
                ip_address=ip_address,
                user_id=current_user.id
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role in {list(allowed_roles)}, current role is '{user_role}'"
            )

        return current_user

    return role_checker
