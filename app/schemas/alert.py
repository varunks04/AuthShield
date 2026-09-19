"""Pydantic schemas for Security Alerts."""

from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional


class SecurityAlertResponse(BaseModel):
    id: int
    timestamp: datetime
    alert_type: str
    severity: str
    user_id: Optional[int] = None
    source_ip: str
    description: str
    status: str

    model_config = ConfigDict(from_attributes=True)


class AlertStatusUpdateRequest(BaseModel):
    status: str = Field(
        ...,
        pattern="^(OPEN|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$",
        description="New alert status: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE"
    )
