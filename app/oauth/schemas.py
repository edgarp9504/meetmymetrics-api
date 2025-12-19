from __future__ import annotations
from typing import Optional
from pydantic import BaseModel


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
