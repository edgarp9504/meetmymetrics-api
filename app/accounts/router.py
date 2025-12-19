from __future__ import annotations

from fastapi import APIRouter, Depends, status # pyright: ignore[reportMissingImports]

from app.auth.dependencies import get_current_user
from app.accounts.schemas import (
    AccountInvitationRequest,
    AccountInvitationAcceptRequest,
    UpgradePlanRequest,
    AccountMemberOut,
    AccountActivityEntry,
)
from app.accounts import service as accounts_service

router = APIRouter(prefix="/accounts", tags=["Accounts"])


@router.get("/plan-info")
def get_account_plan_info(user=Depends(get_current_user)):
    """
    Retorna información del plan de la cuenta y si puede invitar más miembros.
    """
    return accounts_service.get_account_plan_info(user)


@router.post("/invitations", status_code=status.HTTP_201_CREATED)
def create_invitation(
    payload: AccountInvitationRequest,
    user=Depends(get_current_user),
):
    """
    Envía una invitación a un usuario para unirse a la cuenta.
    Solo el owner puede invitar.
    """
    return accounts_service.create_invitation(user, payload)


@router.post("/invitations/accept")
def accept_invitation(payload: AccountInvitationAcceptRequest):
    """
    Acepta una invitación usando un token y crea/asocia el usuario a la cuenta.
    """
    return accounts_service.accept_invitation(payload)


@router.delete("/members/{member_id}")
def remove_member(
    member_id: int,
    user=Depends(get_current_user),
):
    """
    Elimina un miembro de la cuenta.
    Solo el owner puede eliminar miembros (excepto a sí mismo).
    """
    return accounts_service.remove_member(user, member_id)


@router.post("/upgrade-plan")
def upgrade_plan(
    payload: UpgradePlanRequest,
    user=Depends(get_current_user),
):
    """
    Cambia el plan de la cuenta.
    Solo el owner puede realizar esta acción.
    """
    return accounts_service.upgrade_plan(user, payload)


@router.get("/members", response_model=list[AccountMemberOut])
def list_members(user=Depends(get_current_user)):
    """
    Lista los miembros de la cuenta actual.
    """
    return accounts_service.list_members(user)


@router.get("/activity", response_model=list[AccountActivityEntry])
def get_account_activity(user=Depends(get_current_user)):
    """
    Retorna la actividad reciente de la cuenta (auditoría).
    """
    return accounts_service.get_account_activity(user)
