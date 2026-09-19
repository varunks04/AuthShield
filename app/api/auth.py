"""Authentication API endpoints (Register and Login)."""

from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session, joinedload
from app.database.connection import get_db
from app.config import settings
from app.models.user import User
from app.models.role import Role
from app.schemas.auth import UserRegisterRequest, UserLoginRequest, TokenResponse
from app.schemas.user import UserResponse
from app.auth.password import hash_password, verify_password
from app.auth.jwt import create_access_token
from app.auth.permissions import get_client_ip
from app.services.audit_service import AuditService
from app.detection.engine import DetectionEngine

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(
    request: Request,
    payload: UserRegisterRequest,
    db: Session = Depends(get_db)
):
    """
    Registers a new user account with default 'user' role.
    Generates USER_REGISTERED audit log.
    """
    ip_address = get_client_ip(request)
    endpoint = request.url.path

    # Check for duplicate email
    if db.query(User).filter(User.email == payload.email).first():
        AuditService.log_event(
            db=db,
            action="REGISTRATION_FAILED",
            endpoint=endpoint,
            status="FAILURE",
            ip_address=ip_address,
            details=f"Registration rejected: duplicate email '{payload.email}'"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists"
        )

    # Check for duplicate username
    if db.query(User).filter(User.username == payload.username).first():
        AuditService.log_event(
            db=db,
            action="REGISTRATION_FAILED",
            endpoint=endpoint,
            status="FAILURE",
            ip_address=ip_address,
            details=f"Registration rejected: duplicate username '{payload.username}'"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this username already exists"
        )

    # Assign default 'user' role
    user_role = db.query(Role).filter(Role.name == "user").first()
    if not user_role:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user role not configured"
        )

    new_user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role_id=user_role.id,
        status="active"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    AuditService.log_event(
        db=db,
        action="USER_REGISTERED",
        endpoint=endpoint,
        status="SUCCESS",
        ip_address=ip_address,
        user_id=new_user.id,
        details=f"User '{new_user.username}' successfully registered"
    )

    return new_user


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    payload: UserLoginRequest,
    db: Session = Depends(get_db)
):
    """
    Authenticates user with email and password, issuing a signed JWT.
    Monitors failed attempts and triggers brute force / disabled account detection rules.
    """
    ip_address = get_client_ip(request)
    endpoint = request.url.path

    user = db.query(User).options(joinedload(User.role)).filter(User.email == payload.email).first()

    # Case 1: User does not exist
    if not user:
        AuditService.log_event(
            db=db,
            action="LOGIN_FAILED",
            endpoint=endpoint,
            status="FAILURE",
            ip_address=ip_address,
            details=f"Login failed: unknown email '{payload.email}'"
        )
        DetectionEngine.on_login_failed(db, ip_address=ip_address)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Case 2: User account disabled
    if user.status != "active":
        AuditService.log_event(
            db=db,
            action="LOGIN_ATTEMPT_DISABLED_ACCOUNT",
            endpoint=endpoint,
            status="FAILURE",
            ip_address=ip_address,
            user_id=user.id,
            details=f"Login rejected: account '{user.username}' is disabled"
        )
        DetectionEngine.on_disabled_account_attempt(
            db=db,
            user_id=user.id,
            username=user.username,
            ip_address=ip_address
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been disabled. Please contact an administrator."
        )

    # Case 3: Invalid password
    if not verify_password(payload.password, user.password_hash):
        AuditService.log_event(
            db=db,
            action="LOGIN_FAILED",
            endpoint=endpoint,
            status="FAILURE",
            ip_address=ip_address,
            user_id=user.id,
            details=f"Login failed: invalid password for user '{user.username}'"
        )
        DetectionEngine.on_login_failed(db, ip_address=ip_address, user_id=user.id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Case 4: Successful login
    AuditService.log_event(
        db=db,
        action="LOGIN_SUCCESS",
        endpoint=endpoint,
        status="SUCCESS",
        ip_address=ip_address,
        user_id=user.id,
        details=f"User '{user.username}' authenticated successfully"
    )

    token_data = {
        "sub": str(user.id),
        "role": user.role.name if user.role else "user"
    }
    expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(data=token_data, expires_delta=expires_delta)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id,
        username=user.username,
        role=user.role.name if user.role else "user"
    )
