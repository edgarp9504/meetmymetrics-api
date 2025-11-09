from __future__ import annotations

from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from dependencies import get_current_user
from app.db.connection import get_connection
from app.db.migrations import ensure_account_schema
from app.utils.email import send_account_invitation_email
from app.utils.hashing import get_password_hash
from app.utils.validation import validate_password_strength


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


class AccountMemberOut(BaseModel):
    id: int
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    role: str
    invited_by: Optional[int]
    joined_at: datetime


router = APIRouter(prefix="/accounts", tags=["Accounts"])


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

            if user.plan_type == "free":
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM account_members
                    WHERE account_id = %s AND role <> 'owner'
                    """,
                    (user.account_id,),
                )
                member_count = cur.fetchone()[0] or 0

                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM account_invitations
                    WHERE account_id = %s AND status = 'pending'
                    """,
                    (user.account_id,),
                )
                pending_count = cur.fetchone()[0] or 0

                if invitation_row and existing_status == "pending":
                    pending_count -= 1

                if member_count + pending_count >= 1:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Solo puedes invitar a un usuario en el plan gratuito.",
                    )

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
    try:
        conn = get_connection()
        ensure_account_schema(conn)
        now_utc = datetime.utcnow()
        hashed_password = get_password_hash(payload.password)

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, account_id, invited_email, expires_at, status, invited_by_user_id
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
            ) = invitation_row

            expires_at = _normalize_timestamp(expires_at)

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

            cur.execute(
                "UPDATE account_invitations SET status='accepted', accepted_at=%s WHERE id=%s",
                (now_utc, invitation_id),
            )

        conn.commit()
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

    return {"message": "Invitación aceptada. Ya puedes iniciar sesión."}


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
                email=row[1],
                first_name=row[2],
                last_name=row[3],
                role=row[4],
                invited_by=row[5],
                joined_at=row[6],
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

