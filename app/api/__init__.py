"""API router exports."""

from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.audit import router as audit_router
from app.api.alerts import router as alerts_router

__all__ = ["auth_router", "users_router", "audit_router", "alerts_router"]
