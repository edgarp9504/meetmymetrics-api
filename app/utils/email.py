"""Utility helpers for sending transactional emails via Resend."""

from __future__ import annotations

import os

import requests


RESEND_API_KEY = os.getenv("RESEND_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "no-reply@resend.dev")
FRONTEND_URL = os.getenv(
    "FRONTEND_URL", "https://meetmymetrics.azurestaticapps.net"
)
RESEND_URL = "https://api.resend.com/emails"


def _build_verification_html(user_name: str, verification_code: str) -> str:
    recipient_name = user_name.strip() if user_name else ""

    greeting = f"Hola {recipient_name} 👋" if recipient_name else "Hola 👋"

    return f"""
    <html>
        <body style="font-family: Arial, sans-serif;">
            <h2>{greeting}</h2>
            <p>Tu código de verificación para <b>MeetMyMetrics</b> es:</p>
            <div style="font-size: 22px; font-weight: bold; color: #0078D4; margin: 10px 0;">
                {verification_code}
            </div>
            <p>Este código expira en 15 minutos.</p>
            <br/>
            <p>Si no solicitaste este registro, ignora este mensaje.</p>
        </body>
    </html>
    """


def _build_invitation_html(inviter_name: str, invitation_link: str) -> str:
    safe_inviter = inviter_name.strip() if inviter_name else "Alguien de MeetMyMetrics"
    return f"""
    <html>
        <body style="font-family: Arial, sans-serif;">
            <h2>Hola 👋</h2>
            <p><strong>{safe_inviter}</strong> te ha invitado a colaborar en su cuenta de MeetMyMetrics.</p>
            <p style="margin: 24px 0;">
                <a href="{invitation_link}" style="background-color:#0078D4;color:white;padding:12px 24px;text-decoration:none;border-radius:6px;">
                    Aceptar invitación
                </a>
            </p>
            <p>Si el botón no funciona, copia y pega este enlace en tu navegador:</p>
            <p><a href="{invitation_link}">{invitation_link}</a></p>
            <p>Este enlace expira en 72 horas.</p>
        </body>
    </html>
    """


def _log_missing_env(var_name: str) -> None:
    print(f"❌ Variable de entorno no configurada: {var_name}")


def _send(payload: dict) -> None:
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(RESEND_URL, json=payload, headers=headers, timeout=10)
    except requests.RequestException as exc:
        print(f"❌ Excepción al enviar correo con Resend: {exc}")
        return

    if response.ok:
        print(
            f"✅ Correo enviado a {', '.join(payload.get('to', []))} con asunto '{payload.get('subject', '')}'"
        )
    else:
        print(
            "❌ Error al enviar correo "
            f"({response.status_code}): {response.text or response.reason}"
        )


def send_email(payload: dict) -> None:
    if not RESEND_API_KEY:
        _log_missing_env("RESEND_API_KEY")
        return

    if not SENDER_EMAIL:
        _log_missing_env("SENDER_EMAIL")
        return

    to_recipients = payload.get("to")
    if not to_recipients:
        print("❌ Dirección de correo destino no proporcionada.")
        return

    payload.setdefault("from", f"MeetMyMetrics <{SENDER_EMAIL}>")

    _send(payload)


def send_verification_email(to_email: str, user_name: str, verification_code: str) -> None:
    """Send a verification email using the Resend transactional email service."""

    if not to_email:
        print("❌ Dirección de correo destino no proporcionada.")
        return

    html_content = _build_verification_html(user_name, verification_code)

    payload = {
        "from": f"MeetMyMetrics <{SENDER_EMAIL}>",
        "to": [to_email],
        "subject": "Verifica tu cuenta en MeetMyMetrics",
        "html": html_content,
    }

    send_email(payload)



def send_account_invitation_email(to_email: str, inviter_name: str, token: str) -> None:
    if not to_email:
        print("❌ Dirección de correo destino no proporcionada.")
        return

    invitation_link = f"{FRONTEND_URL.rstrip('/')}/invite/accept?token={token}"
    html_content = _build_invitation_html(inviter_name, invitation_link)

    payload = {
        "from": f"MeetMyMetrics <{SENDER_EMAIL}>",
        "to": [to_email],
        "subject": "Has sido invitado a MeetMyMetrics",
        "html": html_content,
    }

    send_email(payload)


__all__ = ["send_email", "send_verification_email", "send_account_invitation_email"]
