from __future__ import annotations

from types import SimpleNamespace
from typing import Optional

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from fastapi import Header, HTTPException, status

from app.auth.routes import SECRET_KEY
from app.db.connection import get_connection


def get_current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except (InvalidTokenError, Exception):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    conn = None
    row = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, email, account_type FROM users WHERE id=%s",
                (user_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to validate user") from exc
    finally:
        if conn:
            conn.close()

    account_type = row[2] if len(row) > 2 else None
    account_limit = _resolve_account_limit(account_type)

    return SimpleNamespace(
        id=row[0],
        email=row[1],
        account_type=account_type,
        account_limit=account_limit,
    )


def _resolve_account_limit(account_type: Optional[str]) -> int:
    if not account_type:
        return 1

    normalized = account_type.lower()
    if normalized in {"free", "personal"}:
        return 1
    return 10
