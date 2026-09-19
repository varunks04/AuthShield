"""Base model declarations."""

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime
from app.database.connection import Base


class TimestampMixin:
    """Provides created_at and updated_at timestamps in UTC."""
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
