from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class AdAccountBase(BaseModel):
    account_name: str
    social_network: str
    account_identifier: str
    currency: Optional[str] = None
    timezone_name: Optional[str] = None
    account_status: Optional[str] = None
    business_id: Optional[str] = None
    business_name: Optional[str] = None
    access_token: Optional[str] = None
    token_expiry: Optional[datetime] = None
    is_active: Optional[bool] = True


class AdAccountCreate(AdAccountBase):
    pass


class AdAccountOut(AdAccountBase):
    id: int
    last_sync: Optional[datetime]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OAuthProviderAccount(BaseModel):
    id: str
    name: Optional[str]
    currency: Optional[str]
    timezone_name: Optional[str]
    account_status: Optional[str]
    business_name: Optional[str] = None
    business_id: Optional[str] = None


class OAuthCallbackResponse(BaseModel):
    accounts: list[OAuthProviderAccount]


class OAuthConnectRequest(BaseModel):
    account_id: str
    account_name: str
    currency: Optional[str] = None
    timezone_name: Optional[str] = None
    account_status: Optional[str] = None
    business_name: Optional[str] = None
    business_id: Optional[str] = None


class OAuthDisconnectRequest(BaseModel):
    account_id: str
