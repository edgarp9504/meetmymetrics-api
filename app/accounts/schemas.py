from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


class AccountInvitationRequest(BaseModel):
    email: EmailStr


class AccountInvitationAcceptRequest(BaseModel):
    token: str = Field(..., min_length=1)
    password: str = Field(..., min_length=8)
    first_name: Optional[str] = None
    last_name: Optional[str] = None


class UpgradePlanRequest(BaseModel):
    plan_type: str = Field(..., min_length=3, max_length=20)


class AccountMemberOut(BaseModel):
    id: int
    user_id: int
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    role: str
    invited_by: Optional[int]
    joined_at: datetime


class AccountActivityEntry(BaseModel):
    action_type: str
    description: Optional[str]
    created_at: datetime

