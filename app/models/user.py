"""User model definition."""

from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from app.database.connection import Base
from app.models.base import TimestampMixin


class User(Base, TimestampMixin):
    """System user representing accounts authenticated and monitored by AuthShield."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    status = Column(String(20), default="active", nullable=False)  # "active" or "disabled"

    role = relationship("Role", back_populates="users")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    security_alerts = relationship("SecurityAlert", back_populates="user", cascade="all, delete-orphan")
