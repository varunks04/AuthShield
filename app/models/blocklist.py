"""Blocked IP model definition for active network containment."""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from app.database.connection import Base


class BlockedIP(Base):
    """Represents an IP address manually blocked by a security analyst."""
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    reason = Column(String(255), nullable=True)
    blocked_by = Column(String(100), default="analyst@authshield.io", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
