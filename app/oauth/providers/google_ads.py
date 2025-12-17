from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

import httpx
from fastapi import HTTPException, status

from app.core.config import settings
from app.oauth.providers.base import OAuthProvider, validate_oauth_response

logger = logging.getLogger(__name__)

GOOGLE_SCOPE = (
    "openid https://www.googleapis.com/auth/userinfo.email "
    "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/adwords"
)


class GoogleAdsProvider(OAuthProvider):
    name = "google"

    def build_authorization_url(self, state: str) -> str:
        client_id = settings.google_ads_client_id
        if not client_id:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Credenciales OAuth no configuradas para google",
            )

        redirect_uri = self.build_redirect_uri()
        logger.info("[GoogleAds] Using redirect_uri for authorization: %s", redirect_uri)
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": GOOGLE_SCOPE,
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
        }
        return f"https://accounts.google.com/o/oauth2/v2/auth?{httpx.QueryParams(params)}"

    def build_redirect_uri(self) -> str:
        # Google Ads requiere que redirect_uri sea un valor estático y exacto.
        # No debe reconstruirse dinámicamente ni derivarse de backend_url.
        redirect_uri = os.getenv("GOOGLE_ADS_REDIRECT_URI")
        if not redirect_uri:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="GOOGLE_ADS_REDIRECT_URI no configurado",
            )
        return redirect_uri

    async def exchange_code_for_token(
        self, code: str, redirect_uri: str, client: httpx.AsyncClient
    ) -> Dict[str, Any]:
        client_id = settings.google_ads_client_id
        client_secret = settings.google_ads_client_secret
        if not client_id or not client_secret:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Credenciales OAuth no configuradas para google",
            )

        enforced_redirect_uri = self.build_redirect_uri()
        if redirect_uri != enforced_redirect_uri:
            logger.warning(
                "[GoogleAds] Overriding provided redirect_uri with static value: %s",
                enforced_redirect_uri,
            )
        logger.info("[GoogleAds] Using redirect_uri for token exchange: %s", enforced_redirect_uri)

        response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": enforced_redirect_uri,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        data = validate_oauth_response(response)
        return {
            "access_token": data["access_token"],
            "refresh_token": data.get("refresh_token"),
            "expires_in": data.get("expires_in"),
            "token_type": data.get("token_type", "Bearer"),
            "scope": data.get("scope"),
        }

    async def fetch_accounts(
        self, access_token: str, client: httpx.AsyncClient
    ) -> List[Dict[str, Any]]:
        developer_token = settings.google_ads_developer_token
        if not developer_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Google Ads developer token no configurado",
            )

        response = await client.get(
            "https://googleads.googleapis.com/v17/customers:listAccessibleCustomers",
            headers={
                "Authorization": f"Bearer {access_token}",
                "developer-token": developer_token,
            },
        )
        data = validate_oauth_response(response)
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

    async def refresh_token(
        self, refresh_token: str, client: httpx.AsyncClient
    ) -> Dict[str, Any]:
        client_id = settings.google_ads_client_id
        client_secret = settings.google_ads_client_secret
        if not client_id or not client_secret:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Credenciales OAuth no configuradas para google",
            )

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
        data = validate_oauth_response(response)
        if "access_token" not in data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Google Ads no devolvió un access_token",
            )
        return data
