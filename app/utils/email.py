from importlib import import_module, util
import logging
import os
from typing import Any, Optional, Type


logger = logging.getLogger(__name__)


def _load_email_client() -> Optional[Type[Any]]:
    """Return the Azure EmailClient class if the SDK is available."""

    if util.find_spec("azure.communication.email") is None:
        return None

    email_module = import_module("azure.communication.email")
    return getattr(email_module, "EmailClient", None)


def send_verification_email(to_email: str, user_name: str, code: str) -> None:
    """Send a verification code email through Azure Communication Services."""

    endpoint = os.getenv("AZURE_COMMUNICATION_ENDPOINT")
    access_key = os.getenv("AZURE_COMMUNICATION_KEY")
    sender = os.getenv("SENDER_EMAIL")
    environment = os.getenv("ENVIRONMENT", "undefined")

    if not endpoint or not access_key:
        logger.error(
            "Azure Communication Services credentials are not configured; "
            "skipping verification email for %s",
            to_email,
        )
        return

    if not sender:
        logger.error("SENDER_EMAIL environment variable is not configured.")
        return

    print("\n===== Azure Communication Service Configuration =====")
    print(f"ENVIRONMENT: {environment}")
    print(f"ENDPOINT: {endpoint}")
    print(f"SENDER_EMAIL: {sender}")
    if access_key:
        print(f"ACCESS_KEY: {access_key[:10]}********")
    else:
        print("ACCESS_KEY: ❌ Not found")
    print("=====================================================\n")

    email_client_cls = _load_email_client()

    if email_client_cls is None:
        logger.error(
            "azure-communication-email package is not installed; cannot send email to %s",
            to_email,
        )
        return

    client = email_client_cls(endpoint, access_key)

    recipient_name = user_name.strip() if user_name else to_email

    subject = "Verifica tu cuenta en MeetMyMetrics"
    html_body = f"""
    <html>
        <body style="font-family:Arial,sans-serif;">
            <h2>¡Hola {recipient_name}!</h2>
            <p>Gracias por registrarte en <strong>MeetMyMetrics</strong>.</p>
            <p>Tu código de verificación es:</p>
            <h1 style="color:#0A2540;">{code}</h1>
            <p>Este código expira en 15 minutos.</p>
            <br>
            <p>Si no creaste una cuenta, puedes ignorar este mensaje.</p>
        </body>
    </html>
    """

    message = {
        "senderAddress": sender,
        "recipients": {"to": [{"address": to_email}]},
        "content": {"subject": subject, "html": html_body},
    }

    try:
        poller = client.begin_send(message)
        result: Optional[dict] = poller.result()
        message_id = None
        if isinstance(result, dict):
            message_id = result.get("id")
        logger.info(
            "Verification email sent to %s%s",
            to_email,
            f" (ID: {message_id})" if message_id else "",
        )
    except Exception as exc:  # pragma: no cover - best effort logging
        logger.exception(
            "Failed to send verification email to %s via Azure Communication Services: %s",
            to_email,
            exc,
        )

