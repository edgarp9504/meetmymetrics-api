from datetime import datetime
from typing import Optional

from fastapi import HTTPException # pyright: ignore[reportMissingImports]
from app.db.connection import get_connection
from app.db.migrations import ensure_account_schema
from app.accounts.schemas import AccountActivityEntry,AccountMemberOut,AccountInvitationAcceptRequest
from app.db.audit import log_action, safe_log_action
from app.utils.validation import validate_password_strength
from app.utils.email import send_email
from app.utils.hashing import get_password_hash

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

def get_account_activity(user):
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
            cur.execute(
                """
                SELECT action_type, description, created_at
                FROM audit_log
                WHERE account_id = %s
                ORDER BY created_at DESC
                LIMIT 50
                """,
                (user.account_id,),
            )
            rows = cur.fetchall()

        return [
            AccountActivityEntry(
                action_type=row[0],
                description=row[1],
                created_at=row[2],
            )
            for row in rows
        ]

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="No se pudo obtener la actividad de la cuenta.",
        ) from exc

    finally:
        if conn:
            conn.close()

def remove_member(user, member_id: int):
    if not getattr(user, "account_id", None):
        raise HTTPException(
            status_code=400,
            detail="El usuario no tiene una cuenta asociada.",
        )

    conn = None
    try:
        conn = get_connection()
        ensure_account_schema(conn)

        # Verificar que el usuario sea owner
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT role
                FROM account_members
                WHERE account_id = %s AND user_id = %s
                """,
                (user.account_id, user.id),
            )
            role_row = cur.fetchone()

        if not role_row or role_row[0] != "owner":
            raise HTTPException(
                status_code=403,
                detail="Solo el propietario puede eliminar miembros.",
            )

        # Obtener miembro a eliminar
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id, role
                FROM account_members
                WHERE id = %s AND account_id = %s
                """,
                (member_id, user.account_id),
            )
            member_row = cur.fetchone()

        if not member_row:
            raise HTTPException(
                status_code=404,
                detail="Miembro no encontrado en esta cuenta.",
            )

        _, member_role = member_row

        if member_role == "owner":
            raise HTTPException(
                status_code=400,
                detail="No es posible eliminar al propietario de la cuenta.",
            )

        # Eliminar miembro
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM account_members
                WHERE id = %s AND account_id = %s
                """,
                (member_id, user.account_id),
            )

        conn.commit()

        log_action(
            conn,
            user.id,
            user.account_id,
            "MEMBER_REMOVED",
            f"Miembro ID {member_id} eliminado",
        )

        return {"message": "Miembro eliminado correctamente."}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as exc:
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail="Error eliminando miembro.",
        ) from exc
    finally:
        if conn:
            conn.close()

def upgrade_plan(user, request):
    if not getattr(user, "account_id", None):
        raise HTTPException(
            status_code=400,
            detail="El usuario no tiene una cuenta asociada.",
        )

    if user.account_role != "owner":
        raise HTTPException(
            status_code=403,
            detail="Solo el propietario puede cambiar el plan.",
        )

    requested_plan = request.plan_type.strip().lower()
    valid_plans = {"free", "pro", "business"}

    if requested_plan not in valid_plans:
        raise HTTPException(
            status_code=400,
            detail="Plan no válido.",
        )

    conn = None
    try:
        conn = get_connection()
        ensure_account_schema(conn)

        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE accounts
                SET plan_type = %s,
                    updated_at = NOW()
                WHERE id = %s
                """,
                (requested_plan, user.account_id),
            )

            if cur.rowcount == 0:
                raise HTTPException(
                    status_code=404,
                    detail="Cuenta no encontrada.",
                )

        conn.commit()

        log_action(
            conn,
            user.id,
            user.account_id,
            "PLAN_UPGRADED",
            f"Cuenta actualizada a {requested_plan.upper()}",
        )

        return {"message": f"Plan actualizado a {requested_plan.upper()} correctamente."}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as exc:
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail="No se pudo actualizar el plan de la cuenta.",
        ) from exc
    finally:
        if conn:
            conn.close()

def list_members(user):
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
            cur.execute(
                """
                SELECT
                    am.id,
                    u.id,
                    u.email,
                    u.first_name,
                    u.last_name,
                    am.role,
                    am.invited_by_user_id,
                    am.created_at
                FROM account_members am
                JOIN users u ON u.id = am.user_id
                WHERE am.account_id = %s
                ORDER BY 
                    CASE WHEN am.role = 'owner' THEN 0 ELSE 1 END,
                    am.created_at
                """,
                (user.account_id,),
            )
            rows = cur.fetchall()

        return [
            AccountMemberOut(
                id=row[0],
                user_id=row[1],
                email=row[2],
                first_name=row[3],
                last_name=row[4],
                role=row[5],
                invited_by=row[6],
                joined_at=row[7],
            )
            for row in rows
        ]

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="No se pudieron obtener los miembros de la cuenta.",
        ) from exc
    finally:
        if conn:
            conn.close()

def _normalize_timestamp(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if getattr(value, "tzinfo", None) is not None:
        return value.replace(tzinfo=None)
    return value


def accept_invitation(payload: AccountInvitationAcceptRequest):
    if not validate_password_strength(payload.password):
        raise HTTPException(
            status_code=400,
            detail=(
                "La contraseña debe tener al menos 8 caracteres, incluyendo mayúsculas, "
                "minúsculas, número y símbolo especial."
            ),
        )

    conn = None
    owner_email = None
    new_user_id: Optional[int] = None

    invited_first_name = (payload.first_name or "").strip()
    invited_last_name = (payload.last_name or "").strip()

    try:
        conn = get_connection()
        ensure_account_schema(conn)

        now_utc = datetime.utcnow()
        hashed_password = get_password_hash(payload.password)

        with conn.cursor() as cur:
            # 1️⃣ Obtener invitación
            cur.execute(
                """
                SELECT
                    id,
                    account_id,
                    invited_email,
                    expires_at,
                    status,
                    invited_by_user_id,
                    invited_first_name,
                    invited_last_name
                FROM account_invitations
                WHERE token = %s
                """,
                (payload.token,),
            )
            invitation = cur.fetchone()

            if not invitation:
                raise HTTPException(
                    status_code=400,
                    detail="Invitación inválida o expirada.",
                )

            (
                invitation_id,
                account_id,
                invited_email,
                expires_at,
                status_value,
                invited_by_user_id,
                invitation_first_name,
                invitation_last_name,
            ) = invitation

            expires_at = _normalize_timestamp(expires_at)

            invited_first_name = (
                (invitation_first_name or "").strip() or invited_first_name
            )
            invited_last_name = (
                (invitation_last_name or "").strip() or invited_last_name
            )

            if status_value != "pending":
                raise HTTPException(
                    status_code=400,
                    detail="La invitación ya fue utilizada o revocada.",
                )

            if expires_at and expires_at < now_utc:
                cur.execute(
                    "UPDATE account_invitations SET status='expired' WHERE id=%s",
                    (invitation_id,),
                )
                raise HTTPException(
                    status_code=400,
                    detail="La invitación ha expirado.",
                )

            # 2️⃣ Crear o actualizar usuario
            cur.execute(
                "SELECT id FROM users WHERE lower(email) = lower(%s)",
                (invited_email,),
            )
            user_row = cur.fetchone()

            if user_row:
                user_id = user_row[0]
                cur.execute(
                    """
                    UPDATE users
                    SET hashed_password = %s,
                        first_name = COALESCE(NULLIF(%s, ''), first_name),
                        last_name = COALESCE(NULLIF(%s, ''), last_name),
                        is_verified = TRUE
                    WHERE id = %s
                    """,
                    (
                        hashed_password,
                        invited_first_name,
                        invited_last_name,
                        user_id,
                    ),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO users (
                        first_name,
                        last_name,
                        email,
                        hashed_password,
                        account_type,
                        company_name,
                        verification_code,
                        verification_expiry,
                        is_verified
                    )
                    VALUES (%s, %s, %s, %s, 'personal', NULL, NULL, NULL, TRUE)
                    RETURNING id
                    """,
                    (
                        invited_first_name,
                        invited_last_name,
                        invited_email,
                        hashed_password,
                    ),
                )
                user_id = cur.fetchone()[0]

            new_user_id = user_id

            # 3️⃣ Asociar a la cuenta
            cur.execute(
                """
                INSERT INTO account_members (account_id, user_id, role, invited_by_user_id)
                VALUES (%s, %s, 'member', %s)
                ON CONFLICT (account_id, user_id)
                DO NOTHING
                """,
                (account_id, user_id, invited_by_user_id),
            )

            # 4️⃣ Marcar invitación como aceptada
            cur.execute(
                """
                UPDATE account_invitations
                SET status='accepted', accepted_at=%s
                WHERE id=%s
                """,
                (now_utc, invitation_id),
            )

            # 5️⃣ Obtener email del owner
            cur.execute(
                """
                SELECT u.email
                FROM users u
                JOIN accounts a ON a.owner_user_id = u.id
                WHERE a.id = %s
                """,
                (account_id,),
            )
            owner_row = cur.fetchone()
            if owner_row:
                owner_email = owner_row[0]

        conn.commit()

        log_action(
            conn,
            new_user_id,
            account_id,
            "INVITATION_ACCEPTED",
            f"{invited_email} se unió a la cuenta",
        )

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as exc:
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail="No se pudo aceptar la invitación.",
        ) from exc
    finally:
        if conn:
            conn.close()

    # 6️⃣ Notificar al owner
    if owner_email:
        invited_full_name = (
            f"{invited_first_name} {invited_last_name}".strip() or invited_email
        )

        send_email(
            {
                "from": "MeetMyMetrics <no-reply@meetmymetrics.com>",
                "to": [owner_email],
                "subject": "Nuevo miembro en tu cuenta MeetMyMetrics",
                "html": f"""
                <p>Hola 👋,</p>
                <p>Tu invitado <b>{invited_full_name}</b> aceptó la invitación y ya forma parte de tu cuenta.</p>
                <p>Saludos,<br>Equipo MeetMyMetrics</p>
                """,
            }
        )

        safe_log_action(
            new_user_id,
            account_id,
            "NOTIFICATION_SENT",
            f"Se notificó al propietario {owner_email}",
        )

    return {"message": "Invitación aceptada. Ya puedes iniciar sesión."}

