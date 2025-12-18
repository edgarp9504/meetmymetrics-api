from __future__ import annotations

from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    String,
    Text,
    TIMESTAMP,
    UniqueConstraint,
    func,
    JSON,
)

from app.db.session import Base


class OAuthToken(Base):
    __tablename__ = "oauth_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(50), nullable=False)
    access_token_encrypted = Column(Text, nullable=False)
    refresh_token_encrypted = Column(Text)
    token_type = Column(String(40))
    expires_at = Column(TIMESTAMP)
    scope = Column(String(255))
    developer_token = Column(String(255))
    customer_id = Column(String(100))
    login_customer_id = Column(String(100))
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint(
            "user_id", "provider", name="uq_oauth_tokens_user_provider"
        ),
    )


class UserAdAccount(Base):
    __tablename__ = "user_ad_accounts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    ad_account_id = Column(
        Integer, ForeignKey("ad_accounts.id", ondelete="CASCADE"), nullable=False
    )
    created_at = Column(TIMESTAMP, server_default=func.now())

    __table_args__ = (
        UniqueConstraint(
            "user_id", "ad_account_id", name="uq_user_ad_account"
        ),
    )


class ApiLog(Base):
    __tablename__ = "api_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(50), nullable=False)
    action = Column(String(50), nullable=False)
    payload = Column(JSON)
    created_at = Column(TIMESTAMP, server_default=func.now())
