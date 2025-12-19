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
    is_active: Optional[bool] = True
    customer_id: Optional[str] = None
    is_manager: Optional[bool] = False


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
    customer_id: Optional[str] = None
    login_customer_id: Optional[str] = None


class OAuthCallbackResponse(BaseModel):
    accounts: list[OAuthProviderAccount]
    customer_id: Optional[str] = None
    login_customer_id: Optional[str] = None


class OAuthConnectRequest(BaseModel):
    account_id: str
    account_name: str
    currency: Optional[str] = None
    timezone_name: Optional[str] = None
    account_status: Optional[str] = None
    business_name: Optional[str] = None
    business_id: Optional[str] = None
    customer_id: Optional[str] = None
    login_customer_id: Optional[str] = None


class OAuthDisconnectRequest(BaseModel):
    account_id: str

