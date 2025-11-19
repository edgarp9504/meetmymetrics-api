from sqlalchemy import (
    Boolean,
    Column,
    Integer,
    String,
    TIMESTAMP,
    UniqueConstraint,
)
from sqlalchemy.sql import func

from database import Base


class AdAccount(Base):
    __tablename__ = "ad_accounts"

    id = Column(Integer, primary_key=True, index=True)
    account_name = Column(String(150), nullable=False)
    social_network = Column(String(50), nullable=False)
    account_identifier = Column(String(100), nullable=False)
    currency = Column(String(10))
    timezone_name = Column(String(100))
    account_status = Column(String(50))
    business_id = Column(String(100))
    business_name = Column(String(150))
    customer_id = Column(String(100))
    is_manager = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(
        TIMESTAMP, server_default=func.now(), onupdate=func.now()
    )
    last_sync = Column(TIMESTAMP)

    __table_args__ = (
        UniqueConstraint(
            "social_network", "account_identifier", name="uq_ad_accounts_identifier"
        ),
    )
