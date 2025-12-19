from fastapi import HTTPException # pyright: ignore[reportMissingImports]
from app.db.connection import get_connection
from app.db.migrations import ensure_account_schema

def create_invitation(user, email: str):
    if user.account_role != "owner":
        raise PermissionError("Solo owner puede invitar")

def get_account_plan_info(user):
    if not getattr(user, "account_id", None):
        raise HTTPException(
            status_code=400,
            detail="El usuario no tiene una cuenta asociada.",
        )

    conn = None
    try:
        conn = get_connection()
        ensure_account_schema(conn)

        with conn.cursor() as cur:
            # Obtener plan
            cur.execute(
                """
                SELECT plan_type
                FROM accounts
                WHERE id = %s
                """,
                (user.account_id,),
            )
            row = cur.fetchone()
            plan_type = row[0] if row else "free"

            # Contar miembros
            cur.execute(
                """
                SELECT COUNT(*)
                FROM account_members
                WHERE account_id = %s
                """,
                (user.account_id,),
            )
            members_count = cur.fetchone()[0]

        PLAN_LIMITS = {
            "free": 2,
            "pro": 5,
            "business": 999,
        }

        limit = PLAN_LIMITS.get(plan_type, 1)

        return {
            "plan_type": plan_type,
            "current_members": members_count,
            "limit": limit,
            "can_invite": members_count < limit,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Error obteniendo información del plan: {exc}",
        ) from exc
    finally:
        if conn:
            conn.close()