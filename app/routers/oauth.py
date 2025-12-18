from __future__ import annotations

from fastapi import APIRouter, Depends, Request # pyright: ignore[reportMissingImports]
from fastapi.responses import RedirectResponse # pyright: ignore[reportMissingImports]
from sqlalchemy.orm import Session

from app.oauth.session_store import ORIGIN_SESSION_KEY, STATE_SESSION_KEY
from app.oauth.service import (
    connect_account,
    disconnect_account,
    handle_callback,
    initiate_login_flow,
    normalize_provider,
)
from app.db.session import get_db
from app.auth.dependencies import get_current_user
from schemas import OAuthConnectRequest, OAuthDisconnectRequest

router = APIRouter(prefix="/auth", tags=["OAuth2 Providers"])
debug_router = APIRouter()


@debug_router.get("/debug/env", tags=["Debug"], include_in_schema=False)
def debug_env_vars():
    return {
        "STATE_SESSION_KEY": STATE_SESSION_KEY,
        "ORIGIN_SESSION_KEY": ORIGIN_SESSION_KEY,
    }


@router.get("/meta/login", response_class=RedirectResponse)
async def meta_login(request: Request):
    return initiate_login_flow(request, provider="meta")


@router.get("/google/login", response_class=RedirectResponse)
async def google_ads_login(request: Request):
    return initiate_login_flow(request, provider="google")


@router.get("/{provider}/login", response_class=RedirectResponse)
async def oauth_login(provider: str, request: Request):
    return initiate_login_flow(request, provider=provider)


@router.get("/google/callback", response_class=RedirectResponse)
async def google_ads_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    return await handle_callback(
        request,
        provider="google",
        code=code,
        state=state,
        error=error,
        db=db,
        user=user,
    )


@router.get("/{provider}/callback", response_class=RedirectResponse)
async def oauth_callback(
    provider: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    normalized_provider = normalize_provider(provider)
    if normalized_provider == "google":
        return await google_ads_callback(
            request=request,
            code=code,
            state=state,
            error=error,
            db=db,
            user=user,
        )

    return await handle_callback(
        request,
        provider=normalized_provider,
        code=code,
        state=state,
        error=error,
        db=db,
        user=user,
    )


@router.post("/{provider}/connect")
def oauth_connect(
    provider: str,
    payload: OAuthConnectRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    return connect_account(provider, payload, db, user)


@router.post("/{provider}/disconnect")
def oauth_disconnect(
    provider: str,
    payload: OAuthDisconnectRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    return disconnect_account(provider, payload, db, user)
