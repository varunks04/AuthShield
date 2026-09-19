"""Pydantic schemas for User entity and administrative management."""

from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List


class RoleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: RoleResponse
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserProfileUpdateRequest(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None


class UserPasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)


class UserRoleUpdateRequest(BaseModel):
    role_name: str = Field(..., description="Role name: user, analyst, or admin")


class UserStatusUpdateRequest(BaseModel):
    status: str = Field(..., pattern="^(active|disabled)$", description="Account status: active or disabled")
