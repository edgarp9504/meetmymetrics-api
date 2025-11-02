from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database import get_db
from dependencies import get_current_user
from models import AdAccount
from schemas import AdAccountCreate, AdAccountOut

router = APIRouter(prefix="/ad_accounts", tags=["Ad Accounts"])


@router.get("/", response_model=list[AdAccountOut])
def get_ad_accounts(user=Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(AdAccount).filter(AdAccount.user_id == user.id).all()


@router.post("/", response_model=AdAccountOut, status_code=status.HTTP_201_CREATED)
def create_ad_account(
    data: AdAccountCreate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ad_account = AdAccount(**data.model_dump(), user_id=user.id)
    db.add(ad_account)
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
