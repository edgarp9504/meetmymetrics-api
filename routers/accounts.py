from __future__ import annotations

from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from dependencies import get_current_user
from app.db.audit import log_action, safe_log_action
from app.db.connection import get_connection
from app.db.migrations import ensure_account_schema
from app.utils.email import send_account_invitation_email, send_email
from app.utils.hashing import get_password_hash
from app.utils.validation import validate_password_strength


PLAN_MEMBER_LIMITS = {
    "free": 2,
    "pro": 5,
    "business": 999,
}


def _normalize_timestamp(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if getattr(value, "tzinfo", None) is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


class AccountInvitationRequest(BaseModel):
    email: EmailStr


class AccountInvitationAcceptRequest(BaseModel):
    token: str = Field(..., min_length=1)
    password: str = Field(..., min_length=8)
    first_name: Optional[str] = None
    last_name: Optional[str] = None


class UpgradePlanRequest(BaseModel):
    plan_type: str = Field(..., min_length=3, max_length=20)


class AccountMemberOut(BaseModel):
    id: int
    user_id: int
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    role: str
    invited_by: Optional[int]
    joined_at: datetime


class AccountActivityEntry(BaseModel):
    action_type: str
    description: Optional[str]
    created_at: datetime


router = APIRouter(prefix="/accounts", tags=["Accounts"])


@router.get("/plan-info")
def get_account_plan_info(user=Depends(get_current_user)):
    """Return plan information and whether the account can invite more members."""

    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT plan_type
                FROM accounts
                WHERE id = %s
                """,
                (user.account_id,),
            )
            plan_row = cur.fetchone()
            plan_type = plan_row[0] if plan_row else "free"

            cur.execute(
                """
                SELECT COUNT(*)
                FROM account_members
                WHERE account_id = %s
                """,
                (user.account_id,),
            )
            current_members = cur.fetchone()[0]

        limit = PLAN_MEMBER_LIMITS.get(plan_type, 1)

        return {
            "plan_type": plan_type,
            "current_members": current_members,
            "limit": limit,
            "can_invite": current_members < limit,
        }
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(
            status_code=500,
            detail=f"Error obteniendo información del plan: {exc}",
        ) from exc
    finally:
        if conn:
            conn.close()


@router.post("/invitations", status_code=status.HTTP_201_CREATED)
def create_invitation(
    payload: AccountInvitationRequest,
    user=Depends(get_current_user),
):
    if not user.account_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario no tiene una cuenta asociada.",
        )

    if user.account_role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Solo el administrador de la cuenta puede invitar usuarios.",
        )

    normalized_email = payload.email.strip().lower()
    if normalized_email == user.email.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No puedes invitarte a ti mismo.",
        )

    conn = None
    inviter_name = user.email
    try:
        conn = get_connection()
        ensure_account_schema(conn)
        now_utc = datetime.utcnow()

        with conn.cursor() as cur:
            cur.execute(
                "SELECT plan_type FROM accounts WHERE id = %s",
                (user.account_id,),
            )
            plan_row = cur.fetchone()
            plan_type = plan_row[0] if plan_row else "free"

            cur.execute(
                "SELECT COUNT(*) FROM account_members WHERE account_id = %s",
                (user.account_id,),
            )
            current_members = cur.fetchone()[0]

            limit = PLAN_MEMBER_LIMITS.get(plan_type, 1)

            if current_members >= limit:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"Tu plan actual ({plan_type}) alcanzó el límite máximo de "
                        f"miembros permitidos ({limit - 1})."
                    ),
                )

        with conn.cursor() as cur:
            cur.execute(
                "SELECT first_name, last_name FROM users WHERE id=%s",
                (user.id,),
            )
            name_row = cur.fetchone()
            if name_row:
                first_name, last_name = name_row
                inviter_name = " ".join(
                    part for part in [first_name or "", last_name or ""] if part
                ).strip() or inviter_name

            cur.execute(
                """
                SELECT 1
                FROM account_members am
                JOIN users u ON u.id = am.user_id
                WHERE am.account_id = %s AND lower(u.email) = %s
                """,
                (user.account_id, normalized_email),
            )
            if cur.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="El usuario ya pertenece a la cuenta.",
                )

            cur.execute(
                """
                SELECT id, status, expires_at
                FROM account_invitations
                WHERE account_id = %s AND lower(invited_email) = %s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (user.account_id, normalized_email),
            )
            invitation_row = cur.fetchone()

            existing_invitation_id = None
            existing_status = None
            if invitation_row:
                existing_invitation_id, existing_status, existing_expires = invitation_row
                existing_expires = _normalize_timestamp(existing_expires)
                if (
                    existing_status == "pending"
                    and existing_expires
                    and existing_expires < now_utc
                ):
                    cur.execute(
                        "UPDATE account_invitations SET status='expired' WHERE id=%s",
                        (existing_invitation_id,),
                    )
                    invitation_row = None
                else:
                    existing_status = invitation_row[1]

            token = token_urlsafe(48)
            expires_at = now_utc + timedelta(hours=72)

            if invitation_row and existing_status == "pending":
                cur.execute(
                    """
                    UPDATE account_invitations
                    SET token = %s,
                        expires_at = %s,
                        status = 'pending',
                        invited_by_user_id = %s,
                        created_at = NOW()
                    WHERE id = %s
                    """,
                    (token, expires_at, user.id, existing_invitation_id),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO account_invitations (
                        account_id,
                        invited_email,
                        token,
                        status,
                        expires_at,
                        invited_by_user_id
                    )
                    VALUES (%s, %s, %s, 'pending', %s, %s)
                    """,
                    (
                        user.account_id,
                        normalized_email,
                        token,
                        expires_at,
                        user.id,
                    ),
                )

        conn.commit()

        try:
            log_action(
                conn,
                user.id,
                user.account_id,
                "INVITATION_SENT",
                f"Se envió una invitación a {normalized_email}",
            )
        except Exception as log_exc:
            print(f"⚠️ No se pudo registrar la auditoría de invitación: {log_exc}")
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as exc:
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudo crear la invitación.",
        ) from exc
    finally:
        if conn:
            conn.close()

    send_account_invitation_email(normalized_email, inviter_name, token)

    return {"message": "Invitación enviada correctamente."}


@router.delete("/members/{member_id}")
def remove_member(member_id: int, user=Depends(get_current_user)):
    """Permite al propietario eliminar un miembro de su cuenta."""

    if not user.account_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario no tiene una cuenta asociada.",
        )

    conn = None
    try:
        conn = get_connection()
        ensure_account_schema(conn)

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
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Solo el propietario puede eliminar miembros.",
            )

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
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Miembro no encontrado en esta cuenta.",
            )

        _, member_role = member_row

        if member_role == "owner":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No es posible eliminar al propietario de la cuenta.",
            )

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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error eliminando miembro: {exc}",
        ) from exc
    finally:
        if conn:
            conn.close()


@router.post("/invitations/accept")
def accept_invitation(payload: AccountInvitationAcceptRequest):
    if not validate_password_strength(payload.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "La contraseña debe tener al menos 8 caracteres, incluyendo mayúsculas, "
                "minúsculas, número y símbolo especial."
            ),
        )

    conn = None
    owner_email = None
    invited_first_name = (payload.first_name or "").strip()
    invited_last_name = (payload.last_name or "").strip()
    new_user_id: Optional[int] = None
    try:
        conn = get_connection()
        ensure_account_schema(conn)
        now_utc = datetime.utcnow()
        hashed_password = get_password_hash(payload.password)

        with conn.cursor() as cur:
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
            invitation_row = cur.fetchone()

            if not invitation_row:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
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
            ) = invitation_row

            expires_at = _normalize_timestamp(expires_at)

            invited_first_name = (
                (invitation_first_name or "").strip() or invited_first_name
            )
            invited_last_name = (
                (invitation_last_name or "").strip() or invited_last_name
            )

            if status_value != "pending":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="La invitación ya fue utilizada o revocada.",
                )

            if expires_at and expires_at < now_utc:
                cur.execute(
                    "UPDATE account_invitations SET status='expired' WHERE id=%s",
                    (invitation_id,),
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="La invitación ha expirado.",
                )

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
                        (payload.first_name or "").strip(),
                        (payload.last_name or "").strip(),
                        user_id,
                    ),
                )
            else:
                first_name = (payload.first_name or "").strip()
                last_name = (payload.last_name or "").strip()
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
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        first_name,
                        last_name,
                        invited_email,
                        hashed_password,
                        "personal",
                        None,
                        None,
                        None,
                        True,
                    ),
                )
                user_id = cur.fetchone()[0]

            cur.execute(
                """
                INSERT INTO account_members (account_id, user_id, role, invited_by_user_id)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (account_id, user_id)
                DO NOTHING
                """,
                (account_id, user_id, "member", invited_by_user_id),
            )

            new_user_id = user_id

            cur.execute(
                "UPDATE account_invitations SET status='accepted', accepted_at=%s WHERE id=%s",
                (now_utc, invitation_id),
            )

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

        try:
            log_action(
                conn,
                new_user_id,
                account_id,
                "INVITATION_ACCEPTED",
                f"{invited_email} se unió a la cuenta",
            )
        except Exception as log_exc:
            print(f"⚠️ No se pudo registrar la auditoría de aceptación: {log_exc}")
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as exc:
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudo aceptar la invitación.",
        ) from exc
    finally:
        if conn:
            conn.close()

    if owner_email:
        subject = "Nuevo miembro en tu cuenta MeetMyMetrics"
        safe_first_name = invited_first_name or ""
        safe_last_name = invited_last_name or ""
        invited_full_name = (f"{safe_first_name} {safe_last_name}").strip() or invited_email
        html_body = f"""
        <p>Hola 👋,</p>
        <p>Tu invitado <b>{invited_full_name}</b> ha aceptado la invitación y se unió a tu cuenta.</p>
        <p>Saludos,<br>El equipo de MeetMyMetrics</p>
        """

        send_email(
            {
                "from": "MeetMyMetrics <no-reply@meetmymetrics.com>",
                "to": [owner_email],
                "subject": subject,
                "html": html_body,
            }
        )

        safe_log_action(
            new_user_id,
            account_id,
            "NOTIFICATION_SENT",
            f"Se notificó al propietario {owner_email}",
        )

    return {"message": "Invitación aceptada. Ya puedes iniciar sesión."}


@router.post("/upgrade-plan")
def upgrade_plan(request: UpgradePlanRequest, user=Depends(get_current_user)):
    if not user.account_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario no tiene una cuenta asociada.",
        )

    if user.account_role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Solo el propietario puede cambiar el plan.",
        )

    requested_plan = request.plan_type.strip().lower()
    valid_plans = {"free", "pro", "business"}
    if requested_plan not in valid_plans:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Plan no válido.")

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
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Cuenta no encontrada.",
                )

        conn.commit()

        try:
            log_action(
                conn,
                user.id,
                user.account_id,
                "PLAN_UPGRADED",
                f"Cuenta actualizada a {requested_plan.upper()}",
            )
        except Exception as log_exc:
            print(f"⚠️ No se pudo registrar la auditoría de cambio de plan: {log_exc}")
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as exc:
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudo actualizar el plan de la cuenta.",
        ) from exc
    finally:
        if conn:
            conn.close()

    return {"message": f"Plan actualizado a {requested_plan.upper()} correctamente."}


@router.get("/members", response_model=list[AccountMemberOut])
def list_members(user=Depends(get_current_user)):
    if not user.account_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
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

        members = [
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
        return members
    except Exception as exc:
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudieron obtener los miembros de la cuenta.",
        ) from exc
    finally:
        if conn:
            conn.close()


@router.get("/activity", response_model=list[AccountActivityEntry])
def get_account_activity(user=Depends(get_current_user)):
    if not user.account_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
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
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudo obtener la actividad de la cuenta.",
        ) from exc
    finally:
        if conn:
            conn.close()

