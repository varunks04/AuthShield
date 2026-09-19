"""Pydantic schemas for Audit Logging."""

from datetime import datetime
from pydantic import BaseModel, ConfigDict
from typing import Optional


class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    user_id: Optional[int] = None
    ip_address: str
    action: str
    endpoint: str
    status: str
    details: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AuditLogCreate(BaseModel):
    user_id: Optional[int] = None
    ip_address: str
    action: str
    endpoint: str
    status: str
    details: Optional[str] = None
