from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class AdAccountBase(BaseModel):
    account_name: str
    social_network: str
    account_identifier: str
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
