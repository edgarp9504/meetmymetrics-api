from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from typing import Any, Dict, List, Optional

import httpx
from app.ad_accounts.router import count_user_accounts
from fastapi import HTTPException, Request, status # pyright: ignore[reportMissingImports]
from fastapi.responses import RedirectResponse # pyright: ignore[reportMissingImports]
from sqlalchemy import and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.oauth.providers.base import HTTPX_TIMEOUT, OAuthProvider
from app.oauth.providers.google_ads import GoogleAdsProvider
from app.oauth.providers.linkedin import LinkedInProvider
from app.oauth.providers.meta import MetaProvider
from app.oauth.providers.tiktok import TikTokProvider
from app.oauth.session_store import load_origin, store_origin, store_state, validate_state
from app.utils.crypto import get_token_encryptor
from models import AdAccount, ApiLog, OAuthToken, UserAdAccount

logger = logging.getLogger(__name__)

SUPPORTED_PROVIDERS = {"meta", "google", "tiktok", "linkedin"}

_provider_registry: Dict[str, OAuthProvider] = {
    "meta": MetaProvider(),
    "google": GoogleAdsProvider(),
    "tiktok": TikTokProvider(),
    "linkedin": LinkedInProvider(),
}


def normalize_provider(provider: str) -> str:
    normalized = provider.lower()
    if normalized == "google_ads":
        normalized = "google"
    if normalized not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Proveedor no soportado"
        )
    return normalized


def _get_provider(provider: str) -> OAuthProvider:
    normalized = normalize_provider(provider)
    return _provider_registry[normalized]


def _build_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=HTTPX_TIMEOUT)


def _log_session_snapshot(request: Request, provider: str, state: str, origin: str) -> None:
    has_cookie = bool(request.headers.get("cookie")) if hasattr(request, "headers") else False
    logger.info(
        "[OAuth %s] Starting login | state_len=%s | session_keys=%s | has_cookie=%s | origin=%s",
        provider,
        len(state),
        list(request.session.keys()),
        has_cookie,
        origin,
    )


def initiate_login_flow(request: Request, provider: str) -> RedirectResponse:
    normalized_provider = normalize_provider(provider)
    origin = (
        request.query_params.get("app_origin")
        or request.query_params.get("origin")
        or request.headers.get("origin")
    )

    if not origin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing app_origin in login request",
        )

    state = token_urlsafe(32)
    _log_session_snapshot(request, normalized_provider, state, origin)

    store_state(request, normalized_provider, state)
    store_origin(request, normalized_provider, origin)

    if normalized_provider == "google":
        authorization_url = GoogleAdsProvider().build_authorization_url(state)
    else:
        authorization_url = _get_provider(normalized_provider).build_authorization_url(state)

    return RedirectResponse(url=authorization_url, status_code=status.HTTP_302_FOUND)


async def handle_callback(
    request: Request,
    provider: str,
    *,
    code: Optional[str],
    state: Optional[str],
    error: Optional[str],
    db: Session,
    user: Any,
) -> RedirectResponse:
    normalized_provider = normalize_provider(provider)

    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code or state"
        )

    logger.info(
        "[OAuth %s] Callback received | state_len=%s | session_keys=%s",
        normalized_provider,
        len(state),
        list(request.session.keys()),
    )

    validate_state(request, normalized_provider, state)
    app_origin = load_origin(request, normalized_provider) or settings.backend_url
    provider_impl = _get_provider(normalized_provider)
    # Delegate redirect_uri handling entirely to the provider to avoid overrides.
    redirect_uri = provider_impl.build_redirect_uri()

    async with _build_client() as client:
        token_data = await provider_impl.exchange_code_for_token(code, redirect_uri, client)
        account_list = await provider_impl.fetch_accounts(token_data["access_token"], client)

    persist_token(db, user.id, normalized_provider, token_data)
    log_event(db, user.id, normalized_provider, "connect_callback", {"accounts": len(account_list)})

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        logger.exception("Failed to persist OAuth callback information", exc_info=exc)
        raise HTTPException(status_code=500, detail="Error storing OAuth information") from exc

    return RedirectResponse(url=f"{app_origin}?connected={normalized_provider}", status_code=302)


def persist_token(db: Session, user_id: int, provider: str, token_data: Dict[str, Any]) -> None:
    encryptor = get_token_encryptor()

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=500, detail="Token de acceso no disponible")

    encrypted_access = encryptor.encrypt(access_token)
    refresh_token = token_data.get("refresh_token")
    encrypted_refresh = encryptor.encrypt(refresh_token) if refresh_token else None

    expires_in = token_data.get("expires_in")
    expires_at = None
    if expires_in:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

    developer_token = None
    login_customer_id = token_data.get("login_customer_id")
    customer_id = token_data.get("customer_id")
    if provider == "google":
        developer_token = settings.google_ads_developer_token
        login_customer_id = login_customer_id or settings.google_ads_login_mcc_id

    existing = (
        db.query(OAuthToken)
        .filter(and_(OAuthToken.user_id == user_id, OAuthToken.provider == provider))
        .one_or_none()
    )

    if existing:
        existing.access_token_encrypted = encrypted_access
        existing.refresh_token_encrypted = encrypted_refresh
        existing.expires_at = expires_at
        existing.token_type = token_data.get("token_type")
        existing.scope = token_data.get("scope")
        existing.developer_token = developer_token
        existing.login_customer_id = login_customer_id
        existing.customer_id = customer_id
    else:
        db.add(
            OAuthToken(
                user_id=user_id,
                provider=provider,
                access_token_encrypted=encrypted_access,
                refresh_token_encrypted=encrypted_refresh,
                expires_at=expires_at,
                token_type=token_data.get("token_type"),
                scope=token_data.get("scope"),
                developer_token=developer_token,
                login_customer_id=login_customer_id,
                customer_id=customer_id,
            )
        )


def log_event(
    db: Session,
    user_id: int,
    provider: str,
    action: str,
    payload: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        db.add(
            ApiLog(
                user_id=user_id,
                provider=provider,
                action=action,
                payload=payload or {},
            )
        )
    except Exception as exc:  # pragma: no cover - logging should not break flow
        logger.warning("Failed to persist API log: %s", exc)


def connect_account(
    provider: str,
    payload: Any,
    db: Session,
    user: Any,
) -> Dict[str, str]:
    normalized_provider = normalize_provider(provider)

    ad_account = (
        db.query(AdAccount)
        .filter(
            and_(
                AdAccount.social_network == normalized_provider,
                AdAccount.account_identifier == payload.account_id,
            )
        )
        .one_or_none()
    )

    account_data = {
        "account_name": payload.account_name,
        "social_network": normalized_provider,
        "account_identifier": payload.account_id,
        "currency": payload.currency,
        "timezone_name": payload.timezone_name,
        "account_status": payload.account_status,
        "business_id": payload.business_id,
        "business_name": payload.business_name,
        "customer_id": payload.customer_id,
        "is_manager": False,
    }

    if normalized_provider == "google":
        google_customer_id = payload.customer_id or payload.account_id
        account_data["customer_id"] = google_customer_id
        account_data["is_manager"] = bool(
            google_customer_id
            and settings.google_ads_login_mcc_id
            and google_customer_id == settings.google_ads_login_mcc_id
        )

    if ad_account:
        for field, value in account_data.items():
            setattr(ad_account, field, value)
    else:
        ad_account = AdAccount(**account_data)
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

    log_event(
        db,
        user.id,
        normalized_provider,
        "connect",
        {"account_id": payload.account_id, "account_name": payload.account_name},
    )

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        logger.exception("Failed to connect ad account", exc_info=exc)
        raise HTTPException(status_code=400, detail="Account identifier already exists") from exc

    return {"message": "Cuenta conectada correctamente."}


def disconnect_account(
    provider: str,
    payload: Any,
    db: Session,
    user: Any,
) -> Dict[str, str]:
    normalized_provider = normalize_provider(provider)

    ad_account = (
        db.query(AdAccount)
        .filter(
            and_(
                AdAccount.social_network == normalized_provider,
                AdAccount.account_identifier == payload.account_id,
            )
        )
        .one_or_none()
    )

    if not ad_account:
        raise HTTPException(status_code=404, detail="Cuenta no encontrada")

    association = (
        db.query(UserAdAccount)
        .filter(
            UserAdAccount.user_id == user.id,
            UserAdAccount.ad_account_id == ad_account.id,
        )
        .one_or_none()
    )

    if not association:
        raise HTTPException(status_code=404, detail="La cuenta no está asociada al usuario")

    db.delete(association)

    remaining_links = (
        db.query(UserAdAccount)
        .filter(UserAdAccount.ad_account_id == ad_account.id)
        .count()
    )

    if remaining_links == 0:
        ad_account.is_active = False

    log_event(
        db,
        user.id,
        normalized_provider,
        "disconnect",
        {"account_id": payload.account_id},
    )

    db.commit()

    return {"message": "Cuenta desconectada correctamente."}


async def refresh_google_ads_token(user_id: int, db: Session) -> Dict[str, Any]:
    token_record = (
        db.query(OAuthToken)
        .filter(and_(OAuthToken.user_id == user_id, OAuthToken.provider == "google"))
        .one_or_none()
    )

    if not token_record or not token_record.refresh_token_encrypted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No hay refresh token configurado para Google Ads",
        )

    encryptor = get_token_encryptor()
    refresh_token = encryptor.decrypt(token_record.refresh_token_encrypted)
    provider_impl = _get_provider("google")

    async with _build_client() as client:
        data = await provider_impl.refresh_token(refresh_token, client)

    access_token = data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=500, detail="Google Ads no devolvió un access_token")

    token_record.access_token_encrypted = encryptor.encrypt(access_token)
    expires_in = data.get("expires_in")
    if expires_in:
        token_record.expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=int(expires_in)
        )
    token_record.token_type = data.get("token_type", token_record.token_type)
    token_record.scope = data.get("scope", token_record.scope)

    db.add(token_record)
    db.commit()
    db.refresh(token_record)
    return data
