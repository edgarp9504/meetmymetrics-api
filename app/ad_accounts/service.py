# app/ad_accounts/service.py

from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models import UserAdAccount


def count_user_accounts(user_id: int, db: Session) -> int:
    return (
        db.query(func.count(UserAdAccount.id))
        .filter(UserAdAccount.user_id == user_id)
        .scalar()
        or 0
    )
