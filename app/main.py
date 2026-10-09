"""AuthShield Main Application Entry Point."""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from app.config import settings
from app.database.connection import SessionLocal
from app.database.init_db import init_db
from app.models.blocklist import BlockedIP
from app.auth.permissions import get_client_ip
from app.services.audit_service import AuditService
from app.api import (
    auth_router,
    users_router,
    audit_router,
    alerts_router,
    remediation_router,
    insights_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # Ensure database schema is created and default seed accounts exist
    init_db()
    yield


app = FastAPI(
    title=f"{settings.PROJECT_NAME} — Identity & Security Monitoring API",
    description=(
        "Security-focused REST API and identity monitoring platform featuring JWT authentication, "
        "server-side Role-Based Access Control (RBAC), security audit logging, IP-aware request monitoring, "
        "rule-based suspicious activity detection, and active threat containment."
    ),
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)




# Global Exception Handler to avoid leaking internal DB or system error details (PRD Section 24)
@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "A database error occurred. Internal details have been redacted for security."}
    )


@app.get("/health", tags=["System"])
def health_check():
    """Service health verification endpoint."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT
    }


# Register API routers
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(audit_router)
app.include_router(alerts_router)
app.include_router(remediation_router)
app.include_router(insights_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
