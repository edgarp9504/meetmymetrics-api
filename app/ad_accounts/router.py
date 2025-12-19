from __future__ import annotations

from app.ad_accounts.service import count_user_accounts
from fastapi import APIRouter, Depends, HTTPException, status # pyright: ignore[reportMissingImports]
from sqlalchemy import and_, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.auth.dependencies import get_current_user
from app.models import AdAccount, UserAdAccount
from app.ad_accounts.schemas import AdAccountCreate, AdAccountOut

router = APIRouter(prefix="/ad_accounts", tags=["Ad Accounts"])


@router.get("/", response_model=list[AdAccountOut])
def get_ad_accounts(user=Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        db.query(AdAccount)
        .join(UserAdAccount, UserAdAccount.ad_account_id == AdAccount.id)
        .filter(UserAdAccount.user_id == user.id)
        .all()
    )


@router.post("/", response_model=AdAccountOut, status_code=status.HTTP_201_CREATED)
def create_ad_account(
    data: AdAccountCreate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    existing = (
        db.query(AdAccount)
        .filter(
            and_(
                AdAccount.social_network == data.social_network,
                AdAccount.account_identifier == data.account_identifier,
            )
        )
        .one_or_none()
    )

    if existing:
        for field, value in data.model_dump().items():
            setattr(existing, field, value)
        ad_account = existing
    else:
        ad_account = AdAccount(**data.model_dump())
        db.add(ad_account)
        db.flush()

    association = (
        db.query(UserAdAccount)
        .filter(
            UserAdAccount.user_id == user.id,
            UserAdAccount.ad_account_id == ad_account.id,
        )
        .one_or_none()
    )

    if not association:
        if count_user_accounts(user.id, db) >= user.account_limit:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Solo puedes conectar una cuenta en el plan gratuito.",
            )
        db.add(UserAdAccount(user_id=user.id, ad_account_id=ad_account.id))

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account identifier already exists.",
        )
    db.refresh(ad_account)
    return ad_account

