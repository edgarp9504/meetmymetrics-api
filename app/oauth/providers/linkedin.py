from __future__ import annotations

from typing import Any, Dict, List

import httpx
from fastapi import HTTPException, status

from app.core.config import settings
from app.oauth.providers.base import OAuthProvider, validate_oauth_response


class LinkedInProvider(OAuthProvider):
    name = "linkedin"

    def build_authorization_url(self, state: str) -> str:
        client_id = settings.linkedin_client_id
        if not client_id:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Credenciales OAuth no configuradas para linkedin",
            )

        redirect_uri = self.build_redirect_uri()
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "r_ads r_ads_reporting",
            "state": state,
        }
        return f"https://www.linkedin.com/oauth/v2/authorization?{httpx.QueryParams(params)}"

    def build_redirect_uri(self) -> str:
        return f"{settings.backend_url}/auth/linkedin/callback"

    async def exchange_code_for_token(
        self, code: str, redirect_uri: str, client: httpx.AsyncClient
    ) -> Dict[str, Any]:
        client_id = settings.linkedin_client_id
        client_secret = settings.linkedin_client_secret
        if not client_id or not client_secret:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Credenciales OAuth no configuradas para linkedin",
            )

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
        response = await client.get(
            "https://api.linkedin.com/v2/adAccounts",
            params={"q": "search"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        data = validate_oauth_response(response)
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
