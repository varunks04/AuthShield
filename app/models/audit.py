"""Audit Log model for recording security-relevant events."""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database.connection import Base


class AuditLog(Base):
    """Central audit log capturing identity events, access attempts, and administrative changes."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    ip_address = Column(String(50), nullable=False, index=True)
    action = Column(String(50), nullable=False, index=True)
    endpoint = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False)  # SUCCESS, FAILURE, DENIED
    details = Column(Text, nullable=True)

    user = relationship("User", back_populates="audit_logs")
