from __future__ import annotations

from typing import Any, Dict, List

import httpx
from fastapi import HTTPException, status

from app.core.config import settings
from app.oauth.providers.base import OAuthProvider, validate_oauth_response


class TikTokProvider(OAuthProvider):
    name = "tiktok"

    def build_authorization_url(self, state: str) -> str:
        client_key = settings.tiktok_client_key
        if not client_key:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Credenciales OAuth no configuradas para tiktok",
            )

        redirect_uri = self.build_redirect_uri()
        params = {
            "client_key": client_key,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "user.info.basic,advertiser.info",
            "state": state,
        }
        return (
            "https://business-api.tiktok.com/open_api/v1.3/oauth2/authorize?"
            f"{httpx.QueryParams(params)}"
        )

    def build_redirect_uri(self) -> str:
        return f"{settings.backend_url}/auth/tiktok/callback"

    async def exchange_code_for_token(
        self, code: str, redirect_uri: str, client: httpx.AsyncClient
    ) -> Dict[str, Any]:
        client_key = settings.tiktok_client_key
        client_secret = settings.tiktok_client_secret
        if not client_key or not client_secret:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Credenciales OAuth no configuradas para tiktok",
            )

        response = await client.post(
            "https://business-api.tiktok.com/open_api/v1.3/oauth2/access_token/",
            json={
                "app_id": client_key,
                "secret": client_secret,
                "auth_code": code,
                "grant_type": "authorized_code",
            },
        )
        data = validate_oauth_response(response)
        token_data = data.get("data", {})
        return {
            "access_token": token_data.get("access_token"),
            "refresh_token": token_data.get("refresh_token"),
            "expires_in": token_data.get("expires_in"),
            "token_type": token_data.get("token_type", "Bearer"),
            "scope": token_data.get("scope"),
        }

    async def fetch_accounts(
        self, access_token: str, client: httpx.AsyncClient
    ) -> List[Dict[str, Any]]:
        response = await client.get(
            "https://business-api.tiktok.com/open_api/v1.3/oauth2/advertiser/get/",
            params={"access_token": access_token},
        )
        data = validate_oauth_response(response)
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
