from __future__ import annotations

import base64
import logging
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

logger = logging.getLogger(__name__)


class TokenEncryptor:
    def __init__(self, key: bytes):
        self._fernet = Fernet(key)

    def encrypt(self, value: str) -> str:
        token = self._fernet.encrypt(value.encode("utf-8"))
        return token.decode("utf-8")

    def decrypt(self, value: str) -> str:
        try:
            decrypted = self._fernet.decrypt(value.encode("utf-8"))
        except InvalidToken as exc:
            raise ValueError("Invalid encrypted token") from exc
        return decrypted.decode("utf-8")


@lru_cache
def get_token_encryptor() -> TokenEncryptor:
    key = settings.token_encryption_key
    if not key:
        raise RuntimeError("Token encryption key is not configured")

    try:
        key_bytes = key.encode("utf-8")
        # Validate the key by attempting to decode base64 urlsafe
        base64.urlsafe_b64decode(key_bytes)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Invalid token encryption key provided", exc_info=exc)
        raise RuntimeError("Invalid token encryption key") from exc

    return TokenEncryptor(key_bytes)
