from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List

import httpx
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

HTTPX_TIMEOUT = 30.0


def validate_oauth_response(response: httpx.Response) -> Dict[str, Any]:
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


class OAuthProvider(ABC):
    name: str

    @abstractmethod
    def build_authorization_url(self, state: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def build_redirect_uri(self) -> str:
        raise NotImplementedError

    @abstractmethod
    async def exchange_code_for_token(
        self, code: str, redirect_uri: str, client: httpx.AsyncClient
    ) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def fetch_accounts(
        self, access_token: str, client: httpx.AsyncClient
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError
