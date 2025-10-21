import logging
import os
import smtplib
from email.message import EmailMessage


logger = logging.getLogger(__name__)


def send_verification_email(email: str, code: str) -> None:
    """Send the verification code to the user via email.

    Tries to use Azure Communication Service Email if the
    ``AZURE_COMM_CONNECTION_STRING`` environment variable is configured.
    Otherwise falls back to using a local SMTP relay. Errors are logged but
    not raised to avoid interrupting the registration flow.
    """

    subject = "Verifica tu cuenta"
    body = f"Tu código de verificación es: {code}"
    sender = os.getenv("SENDER_EMAIL", "no-reply@meetmymetrics.com")
    connection_string = os.getenv("AZURE_COMM_CONNECTION_STRING")

    if connection_string:
        try:
            from azure.communication.email import EmailClient  # type: ignore

            email_client = EmailClient.from_connection_string(connection_string)
            poller = email_client.begin_send(
                {
                    "senderAddress": sender,
                    "recipients": {"to": [{"address": email}]},
                    "content": {"subject": subject, "plainText": body},
                }
            )
            poller.result()
            return
        except Exception as exc:  # pragma: no cover - best effort logging
            logger.exception(
                "Failed to send verification email via Azure Communication Service: %s",
                exc,
            )

    try:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = sender
        message["To"] = email
        message.set_content(body)

        with smtplib.SMTP("localhost") as smtp:
            smtp.send_message(message)
    except Exception as exc:  # pragma: no cover - best effort logging
        logger.exception("Failed to send verification email via SMTP: %s", exc)

