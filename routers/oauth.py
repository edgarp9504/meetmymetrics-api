from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from typing import Any, Dict, List, Optional
import urllib.parse
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.utils.crypto import get_token_encryptor
from database import get_db
from dependencies import get_current_user
from models import AdAccount, ApiLog, OAuthToken, UserAdAccount
from routers.ad_accounts import count_user_accounts
from schemas import (
    OAuthConnectRequest,
    OAuthDisconnectRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["OAuth2 Providers"])
debug_router = APIRouter()


@debug_router.get("/debug/env", tags=["Debug"], include_in_schema=False)
def debug_env_vars() -> Dict[str, Optional[str]]:
    """Endpoint temporal para depurar las variables de entorno OAuth de Meta.

    ⚠️ IMPORTANTE: eliminar este endpoint antes de pasar a producción.
    """

    meta_client_id = os.getenv("META_CLIENT_ID")
    meta_client_secret = os.getenv("META_CLIENT_SECRET")
    meta_redirect_uri = os.getenv("META_REDIRECT_URI")

    return {
        "META_CLIENT_ID": meta_client_id,
        "META_CLIENT_SECRET": meta_client_secret,
        "META_REDIRECT_URI": meta_redirect_uri,
    }

STATE_SESSION_KEY = "oauth_states"
SUPPORTED_PROVIDERS = {"meta", "google", "tiktok", "linkedin", "google_ads"}
SCOPE = (
    "openid https://www.googleapis.com/auth/userinfo.email "
    "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/adwords"
)


# Instrumented Meta OAuth login endpoint for detailed debugging
@router.get("/meta/login")
def meta_login(request: Request, origin: str | None = None):
    """
    Endpoint para iniciar el flujo OAuth2 con Meta (Facebook/Instagram)
    con logging detallado para diagnóstico.
    """

    try:
        meta_client_id = os.getenv("META_CLIENT_ID")
        meta_client_secret = os.getenv("META_CLIENT_SECRET")
        meta_redirect_uri = os.getenv("META_REDIRECT_URI")

        logging.info("🔹 [OAuth Meta] Iniciando flujo de autenticación...")
        logging.info(
            "📦 Variables cargadas -> CLIENT_ID: %s, REDIRECT_URI: %s",
            meta_client_id,
            meta_redirect_uri,
        )

        if not meta_client_id or not meta_client_secret or not meta_redirect_uri:
            logging.error("🚨 [OAuth Meta] Variables de entorno faltantes")
            raise HTTPException(
                status_code=503,
                detail="Credenciales OAuth no configuradas para meta",
            )

        state = "secure_state_1234"
        encoded_redirect_uri = urllib.parse.quote(meta_redirect_uri, safe="")
        auth_url = (
            "https://www.facebook.com/v20.0/dialog/oauth?"
            f"client_id={meta_client_id}"
            f"&redirect_uri={encoded_redirect_uri}"
            f"&scope=ads_read,business_management,read_insights"
            f"&state={state}"
        )

        logging.info("🔗 [OAuth Meta] URL generada: %s", auth_url)
        if origin:
            logging.info("🌍 [Frontend Origin] %s", origin)

        return {"auth_url": auth_url, "state": state}

    except Exception as exc:  # pylint: disable=broad-except
        logging.exception("❌ [OAuth Meta] Error inesperado: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Error interno OAuth Meta: {exc}",
        ) from exc


@router.get("/{provider}/login", response_class=RedirectResponse)
async def oauth_login(provider: str, request: Request):
    provider = _normalize_provider(provider)

    app_origin = (
        request.query_params.get("app_origin")
        or request.query_params.get("origin")
        or request.headers.get("origin")
    )

    if not app_origin:
        raise HTTPException(
            status_code=400,
            detail="Missing app_origin in Google login request"
        )

    state = token_urlsafe(32)

    _store_state(request, provider, {"state": state, "app_origin": app_origin})

    print(
        ">>> STATE_GENERADO =",
        state,
        flush=True,
    )
    print(
        ">>> ORIGIN_RECIBIDO =",
        app_origin,
        flush=True,
    )

    if provider == "google":
        client_id, _ = _require_credentials(provider)
        redirect_uri = _build_redirect_uri(provider)
        print(
            ">>> REDIRECT_URI_USADO_POR_BACKEND =",
            redirect_uri,
            flush=True,
        )
        google_auth_url = (
            "https://accounts.google.com/o/oauth2/v2/auth"
            f"?client_id={client_id}"
            f"&redirect_uri={redirect_uri}"
            f"&response_type=code"
            f"&scope={SCOPE}"
            f"&state={state}"
            "&access_type=offline"
            "&prompt=consent"
        )
        return RedirectResponse(url=google_auth_url)

    authorization_url = _build_authorization_url(provider)
    url_with_state = f"{authorization_url}&state={state}"

    return RedirectResponse(url=url_with_state)


@router.get("/{provider}/callback", response_class=RedirectResponse)
async def oauth_callback(
    provider: str,
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    provider = _normalize_provider(provider)

    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    if not code or not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code or state")

    app_origin = _validate_state(request, provider, state)

    redirect_uri = _build_redirect_uri(provider)
    token_data = await _exchange_code_for_token(provider, code, redirect_uri)

    account_list = await _fetch_provider_accounts(provider, token_data["access_token"])

    _persist_token(db, user.id, provider, token_data)
    _log_event(db, user.id, provider, "connect_callback", {"accounts": len(account_list)})

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        logger.exception("Failed to persist OAuth callback information", exc_info=exc)
        raise HTTPException(status_code=500, detail="Error storing OAuth information") from exc

    return RedirectResponse(url=f"{app_origin}?connected={provider}", status_code=302)


@router.post("/{provider}/connect")
def oauth_connect(
    provider: str,
    payload: OAuthConnectRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    provider = _normalize_provider(provider)

    ad_account = (
        db.query(AdAccount)
        .filter(
            and_(
                AdAccount.social_network == provider,
                AdAccount.account_identifier == payload.account_id,
            )
        )
        .one_or_none()
    )

    account_data = {
        "account_name": payload.account_name,
        "social_network": provider,
        "account_identifier": payload.account_id,
        "currency": payload.currency,
        "timezone_name": payload.timezone_name,
        "account_status": payload.account_status,
        "business_id": payload.business_id,
        "business_name": payload.business_name,
        "customer_id": payload.customer_id,
        "is_manager": False,
    }

    if provider == "google":
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

    _log_event(
        db,
        user.id,
        provider,
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


@router.post("/{provider}/disconnect")
def oauth_disconnect(
    provider: str,
    payload: OAuthDisconnectRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    provider = _normalize_provider(provider)

    ad_account = (
        db.query(AdAccount)
        .filter(
            and_(
                AdAccount.social_network == provider,
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

    _log_event(
        db,
        user.id,
        provider,
        "disconnect",
        {"account_id": payload.account_id},
    )

    db.commit()

    return {"message": "Cuenta desconectada correctamente."}


def _normalize_provider(provider: str) -> str:
    normalized = provider.lower()
    if normalized == "google_ads":
        normalized = "google"
    if normalized not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Proveedor no soportado")
    return normalized


def _store_state(request: Request, provider: str, value: dict):
    state_container = request.session.get(STATE_SESSION_KEY, {})
    state_container[provider] = value
    request.session[STATE_SESSION_KEY] = state_container


def _validate_state(request: Request, provider: str, state: str):
    state_container = request.session.get(STATE_SESSION_KEY, {})
    record = state_container.pop(provider, None)
    request.session[STATE_SESSION_KEY] = state_container

    if not record or record["state"] != state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state parameter")

    return record["app_origin"]


def _build_authorization_url(provider: str) -> str:
    redirect_uri = _build_redirect_uri(provider)

    if provider == "meta":
        client_id, _ = _require_credentials(provider)
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "ads_read,read_insights,pages_show_list",
        }
        return f"https://www.facebook.com/v20.0/dialog/oauth?{urlencode(params)}"

    if provider == "tiktok":
        client_key, _ = _require_credentials(provider)
        params = {
            "client_key": client_key,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "user.info.basic,advertiser.info",
        }
        return f"https://business-api.tiktok.com/open_api/v1.3/oauth2/authorize?{urlencode(params)}"

    if provider == "linkedin":
        client_id, _ = _require_credentials(provider)
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "r_ads r_ads_reporting",
        }
        return f"https://www.linkedin.com/oauth/v2/authorization?{urlencode(params)}"

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Proveedor no soportado")


def _build_redirect_uri(provider: str) -> str:
    if provider == "google":
        redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
        parsed_redirect = urllib.parse.urlparse(redirect_uri or "")
        if not redirect_uri or (
            parsed_redirect.hostname and parsed_redirect.hostname.lower() == "localhost"
        ):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="GOOGLE_REDIRECT_URI no configurado",
            )
        return redirect_uri

    return f"{settings.backend_url}/auth/{provider}/callback"


async def _exchange_code_for_token(provider: str, code: str, redirect_uri: str) -> Dict[str, Any]:
    client_id, client_secret = _require_credentials(provider)

    async with httpx.AsyncClient(timeout=30.0) as client:
        if provider == "meta":
            response = await client.get(
                "https://graph.facebook.com/v20.0/oauth/access_token",
                params={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uri": redirect_uri,
                    "code": code,
                },
            )
            data = _validate_oauth_response(response)

            long_lived = await client.get(
                "https://graph.facebook.com/v20.0/oauth/access_token",
                params={
                    "grant_type": "fb_exchange_token",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "fb_exchange_token": data["access_token"],
                },
            )
            long_data = _validate_oauth_response(long_lived)
            return {
                "access_token": long_data.get("access_token", data["access_token"]),
                "refresh_token": None,
                "expires_in": long_data.get("expires_in"),
                "token_type": long_data.get("token_type", "Bearer"),
                "scope": "ads_read,read_insights,pages_show_list",
            }

        if provider == "google":
            response = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            data = _validate_oauth_response(response)
            return {
                "access_token": data["access_token"],
                "refresh_token": data.get("refresh_token"),
                "expires_in": data.get("expires_in"),
                "token_type": data.get("token_type", "Bearer"),
                "scope": data.get("scope"),
            }

        if provider == "tiktok":
            response = await client.post(
                "https://business-api.tiktok.com/open_api/v1.3/oauth2/token",
                json={
                    "client_key": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "grant_type": "authorized_code",
                },
            )
            data = _validate_oauth_response(response)
            token_info = data.get("data", {})
            return {
                "access_token": token_info.get("access_token"),
                "refresh_token": token_info.get("refresh_token"),
                "expires_in": token_info.get("expires_in"),
                "token_type": "Bearer",
                "scope": token_info.get("scope"),
            }

        if provider == "linkedin":
            response = await client.post(
                "https://www.linkedin.com/oauth/v2/accessToken",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            data = _validate_oauth_response(response)
            return {
                "access_token": data["access_token"],
                "refresh_token": data.get("refresh_token"),
                "expires_in": data.get("expires_in"),
                "token_type": data.get("token_type", "Bearer"),
                "scope": data.get("scope"),
            }

    raise HTTPException(status_code=500, detail="No se pudo obtener el token de acceso")


async def _fetch_provider_accounts(provider: str, access_token: str) -> List[Dict[str, Any]]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        if provider == "meta":
            response = await client.get(
                "https://graph.facebook.com/v20.0/me/adaccounts",
                params={
                    "fields": "id,name,currency,timezone_name,account_status,business",
                    "access_token": access_token,
                },
            )
            data = _validate_oauth_response(response)
            accounts = []
            for account in data.get("data", []):
                business = account.get("business") or {}
                accounts.append(
                    {
                        "id": account.get("id"),
                        "name": account.get("name"),
                        "currency": account.get("currency"),
                        "timezone_name": account.get("timezone_name"),
                        "status": account.get("account_status"),
                        "business_name": business.get("name"),
                        "business_id": business.get("id"),
                    }
                )
            return accounts

        if provider == "google":
            developer_token = settings.google_ads_developer_token
            if not developer_token:
                raise HTTPException(
                    status_code=503,
                    detail="Google Ads developer token no configurado",
                )

            response = await client.get(
                "https://googleads.googleapis.com/v17/customers:listAccessibleCustomers",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "developer-token": developer_token,
                },
            )
            data = _validate_oauth_response(response)
            accounts = []
            for resource_name in data.get("resourceNames", []):
                customer_id = resource_name.split("/")[-1]
                accounts.append(
                    {
                        "id": customer_id,
                        "name": resource_name,
                        "currency": None,
                        "timezone_name": None,
                        "status": None,
                        "customer_id": customer_id,
                        "login_customer_id": settings.google_ads_login_mcc_id,
                    }
                )
            return accounts

        if provider == "tiktok":
            response = await client.get(
                "https://business-api.tiktok.com/open_api/v1.3/oauth2/advertiser/get/",
                params={"access_token": access_token},
            )
            data = _validate_oauth_response(response)
            advertisers = data.get("data", {}).get("list", [])
            accounts = []
            for advertiser in advertisers:
                accounts.append(
                    {
                        "id": advertiser.get("advertiser_id"),
                        "name": advertiser.get("advertiser_name"),
                        "currency": advertiser.get("currency"),
                        "timezone_name": advertiser.get("timezone"),
                        "status": advertiser.get("status"),
                        "business_name": advertiser.get("corporation_name"),
                        "business_id": advertiser.get("corporation_id"),
                    }
                )
            return accounts

        if provider == "linkedin":
            response = await client.get(
                "https://api.linkedin.com/v2/adAccounts",
                params={"q": "search"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            data = _validate_oauth_response(response)
            accounts = []
            for account in data.get("elements", []):
                account_info = account.get("reference") or {}
                accounts.append(
                    {
                        "id": account.get("id") or account_info.get("id"),
                        "name": account.get("name") or account_info.get("name"),
                        "currency": account.get("currency") or account_info.get("currency"),
                        "timezone_name": account.get("timezone") or account_info.get("timezone"),
                        "status": account.get("status"),
                    }
                )
            return accounts

    raise HTTPException(status_code=500, detail="No se pudieron obtener las cuentas publicitarias")


def _require_credentials(provider: str) -> tuple[str, str]:
    if provider == "meta":
        client_id = settings.meta_app_id
        client_secret = settings.meta_app_secret
    elif provider == "google":
        client_id = settings.google_ads_client_id
        client_secret = settings.google_ads_client_secret
    elif provider == "tiktok":
        client_id = settings.tiktok_client_key
        client_secret = settings.tiktok_client_secret
    elif provider == "linkedin":
        client_id = settings.linkedin_client_id
        client_secret = settings.linkedin_client_secret
    else:  # pragma: no cover
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Proveedor no soportado")

    if not client_id or not client_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Credenciales OAuth no configuradas para {provider}",
        )

    return client_id, client_secret


def _validate_oauth_response(response: httpx.Response) -> Dict[str, Any]:
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:  # pragma: no cover - network failure path
        logger.error(
            "OAuth provider request failed: %s", exc.response.text, exc_info=exc
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Error en la comunicación con el proveedor OAuth",
        ) from exc

    try:
        return response.json()
    except ValueError as exc:  # pragma: no cover - defensive
        logger.error("Invalid JSON received from provider", exc_info=exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Respuesta inválida del proveedor OAuth",
        ) from exc


def _persist_token(db: Session, user_id: int, provider: str, token_data: Dict[str, Any]) -> None:
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
        .filter(
            and_(OAuthToken.user_id == user_id, OAuthToken.provider == provider)
        )
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


async def refresh_google_ads_token(user_id: int, db: Session) -> Dict[str, Any]:
    """Refresh and persist a new Google Ads access token for a user."""

    token_record = (
        db.query(OAuthToken)
        .filter(
            and_(OAuthToken.user_id == user_id, OAuthToken.provider == "google")
        )
        .one_or_none()
    )

    if not token_record or not token_record.refresh_token_encrypted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No hay refresh token configurado para Google Ads",
        )

    encryptor = get_token_encryptor()
    refresh_token = encryptor.decrypt(token_record.refresh_token_encrypted)
    client_id, client_secret = _require_credentials("google")

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    data = _validate_oauth_response(response)
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


def _log_event(
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
