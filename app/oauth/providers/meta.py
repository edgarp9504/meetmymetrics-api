from __future__ import annotations

import os
from typing import Any, Dict, List

import httpx
from fastapi import HTTPException, status

from app.core.config import settings
from app.oauth.providers.base import OAuthProvider, validate_oauth_response

META_SCOPE = "ads_read,read_insights,pages_show_list"


class MetaProvider(OAuthProvider):
    name = "meta"

    def build_authorization_url(self, state: str) -> str:
        client_id = settings.meta_app_id
        if not client_id:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Credenciales OAuth no configuradas para meta",
            )

        redirect_uri = self.build_redirect_uri()
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": META_SCOPE,
            "state": state,
        }
        return f"https://www.facebook.com/v20.0/dialog/oauth?{httpx.QueryParams(params)}"

    def build_redirect_uri(self) -> str:
        redirect_uri = os.getenv("META_REDIRECT_URI") or f"{settings.backend_url}/auth/meta/callback"
        return redirect_uri

    async def exchange_code_for_token(
        self, code: str, redirect_uri: str, client: httpx.AsyncClient
    ) -> Dict[str, Any]:
        client_id = settings.meta_app_id
        client_secret = settings.meta_app_secret
        if not client_id or not client_secret:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Credenciales OAuth no configuradas para meta",
            )

        response = await client.get(
            "https://graph.facebook.com/v20.0/oauth/access_token",
            params={
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "code": code,
            },
        )
        data = validate_oauth_response(response)

        long_lived = await client.get(
            "https://graph.facebook.com/v20.0/oauth/access_token",
            params={
                "grant_type": "fb_exchange_token",
                "client_id": client_id,
                "client_secret": client_secret,
                "fb_exchange_token": data["access_token"],
            },
        )
        long_data = validate_oauth_response(long_lived)
        return {
            "access_token": long_data.get("access_token", data["access_token"]),
            "refresh_token": None,
            "expires_in": long_data.get("expires_in"),
            "token_type": long_data.get("token_type", "Bearer"),
            "scope": META_SCOPE,
        }

    async def fetch_accounts(
        self, access_token: str, client: httpx.AsyncClient
    ) -> List[Dict[str, Any]]:
        response = await client.get(
            "https://graph.facebook.com/v20.0/me/adaccounts",
            params={
                "fields": "id,name,currency,timezone_name,account_status,business",
                "access_token": access_token,
            },
        )
        data = validate_oauth_response(response)
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
