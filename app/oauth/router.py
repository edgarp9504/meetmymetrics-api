from __future__ import annotations

from fastapi import APIRouter, Depends, Request # pyright: ignore[reportMissingImports]
from fastapi.responses import RedirectResponse # pyright: ignore[reportMissingImports]
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.auth.dependencies import get_current_user
from app.oauth.schemas import (
    OAuthConnectRequest,
    OAuthDisconnectRequest,
)
from app.oauth.session_store import (
    ORIGIN_SESSION_KEY,
    STATE_SESSION_KEY,
)
from app.oauth.service import (
    connect_account,
    disconnect_account,
    handle_callback,
    initiate_login_flow,
    normalize_provider,
)

router = APIRouter(prefix="/oauth", tags=["OAuth Providers"])
debug_router = APIRouter(prefix="/oauth/debug", tags=["OAuth Debug"])


@debug_router.get("/env", include_in_schema=False)
def debug_env_vars():
    return {
        "STATE_SESSION_KEY": STATE_SESSION_KEY,
        "ORIGIN_SESSION_KEY": ORIGIN_SESSION_KEY,
    }


@router.get("/{provider}/login", response_class=RedirectResponse)
async def oauth_login(provider: str, request: Request):
    normalized_provider = normalize_provider(provider)
    return initiate_login_flow(request, provider=normalized_provider)


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
    return await handle_callback(
        request=request,
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
    normalized_provider = normalize_provider(provider)
    return connect_account(normalized_provider, payload, db, user)


@router.post("/{provider}/disconnect")
def oauth_disconnect(
    provider: str,
    payload: OAuthDisconnectRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    normalized_provider = normalize_provider(provider)
    return disconnect_account(normalized_provider, payload, db, user)
