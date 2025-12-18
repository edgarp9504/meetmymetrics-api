from __future__ import annotations

from types import SimpleNamespace
from typing import Optional

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from fastapi import Header, HTTPException, status

from app.core.security_keys import ALGORITHM, SECRET_KEY
from app.db.connection import get_connection
from app.db.migrations import ensure_account_schema


def get_current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
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
        ensure_account_schema(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.email, am.account_id, am.role, a.plan_type, u.account_type
                FROM users u
                LEFT JOIN account_members am ON am.user_id = u.id
                LEFT JOIN accounts a ON a.id = am.account_id
                WHERE u.id = %s
                ORDER BY CASE WHEN am.role = 'owner' THEN 0 ELSE 1 END NULLS LAST
                LIMIT 1
                """,
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

    account_id = row[2]
    account_role = row[3]
    plan_type = row[4] or "free"
    legacy_account_type = row[5] if len(row) > 5 else None
    account_limit = _resolve_account_limit(plan_type)

    return SimpleNamespace(
        id=row[0],
        email=row[1],
        account_id=account_id,
        account_role=account_role,
        plan_type=plan_type,
        account_type=legacy_account_type,
        account_limit=account_limit,
    )


def _resolve_account_limit(plan_type: Optional[str]) -> int:
    if not plan_type:
        return 1

    normalized = plan_type.lower()
    if normalized == "free":
        return 1
    return 10
