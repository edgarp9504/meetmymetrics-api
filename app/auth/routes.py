import json
import logging
import random
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from typing import Deque, Dict, Optional
from urllib.parse import urlparse

import jwt
from jwt import InvalidTokenError
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.auth.schemas import (
    UpdatePasswordRequest,
    UserLogin,
    UserRegister,
    VerifyCodeRequest,
)
from app.core.config import settings
from app.core.security import create_access_token
from app.db.connection import get_connection
from app.utils.hashing import get_password_hash, verify_password
from app.utils.validation import (
    is_suspicious_email,
    validate_email_address,
    validate_password_strength,
)
from app.utils.email import send_verification_email

router = APIRouter()
logger = logging.getLogger(__name__)

SECRET_KEY = "super_secret_key"

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_ATTEMPTS = 3
_registration_attempts: Dict[str, Deque[datetime]] = defaultdict(deque)

oauth = OAuth()
GOOGLE_OAUTH_ENABLED = bool(
    settings.google_client_id and settings.google_client_secret
)

if GOOGLE_OAUTH_ENABLED:
    oauth.register(
        name="google",
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
else:
    logger.error("Google OAuth credentials are not configured")


def _build_post_message_html(payload: dict, message: str, origin: str) -> str:
    payload_json = json.dumps(payload)
    origin_json = json.dumps(origin)
    return f"""
    <!DOCTYPE html>
    <html lang=\"en\">
    <head>
        <meta charset=\"UTF-8\" />
        <title>Authentication Status</title>
    </head>
    <body>
        <script>
            (function () {{
                var payload = {payload_json};
                if (window.opener && typeof window.opener.postMessage === 'function') {{
                    window.opener.postMessage(payload, {origin_json});
                }}
                window.close();
            }})();
        </script>
        <p>{message}</p>
    </body>
    </html>
    """


def _validate_app_origin(app_origin: Optional[str]) -> str:
    if not app_origin:
        raise ValueError("Missing app_origin")

    parsed = urlparse(app_origin)

    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise ValueError("Invalid app_origin")

    origin = f"{parsed.scheme}://{parsed.netloc}"
    return origin


@router.post("/register")
def register(user: UserRegister, request: Request):
    conn = None
    cur = None

    verification_code = f"{random.randint(100000, 999999)}"
    verification_expiry = datetime.utcnow() + timedelta(minutes=10)

    client_ip = "unknown"
    if request and request.client and request.client.host:
        client_ip = request.client.host

    now = datetime.utcnow()
    attempts = _registration_attempts[client_ip]
    while attempts and (now - attempts[0]).total_seconds() > RATE_LIMIT_WINDOW_SECONDS:
        attempts.popleft()

    if len(attempts) >= RATE_LIMIT_MAX_ATTEMPTS:
        logger.warning("Rate limit exceeded for IP %s", client_ip)
        return JSONResponse(
            status_code=429,
            content={"error": "Demasiados intentos de registro. Inténtalo de nuevo más tarde."},
        )

    attempts.append(now)

    try:
        normalized_email = validate_email_address(user.email)
    except ValueError as exc:
        logger.warning(
            "Invalid email received during registration from %s: %s",
            client_ip,
            exc,
        )
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid email address."},
        )

    if is_suspicious_email(normalized_email):
        logger.warning(
            "Suspicious email blocked during registration: %s from %s",
            normalized_email,
            client_ip,
        )
        return JSONResponse(
            status_code=400,
            content={"error": "Correo sospechoso o automatizado detectado."},
        )

    if not validate_password_strength(user.password):
        logger.warning("Weak password rejected for email %s from %s", normalized_email, client_ip)
        return JSONResponse(
            status_code=400,
            content={
                "error": "La contraseña debe tener al menos 8 caracteres, incluyendo mayúsculas, minúsculas, número y símbolo especial.",
            },
        )

    first_name = user.first_name
    last_name = user.last_name
    account_type = user.account_type
    company_name = user.company_name

    if account_type == "agencia" and not company_name:
        logger.warning(
            "Missing company_name for agency account during registration: %s from %s",
            normalized_email,
            client_ip,
        )
        return JSONResponse(
            status_code=400,
            content={"error": "El nombre de la empresa es obligatorio para cuentas tipo agencia."},
        )

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("SELECT 1 FROM users WHERE email=%s", (normalized_email,))
        if cur.fetchone():
            logger.warning(
                "Attempt to register an already registered email: %s from %s",
                normalized_email,
                client_ip,
            )
            return JSONResponse(
                status_code=400,
                content={"error": "Email already registered"},
            )

        hashed_password = get_password_hash(user.password)
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
            """,
            (
                first_name,
                last_name,
                normalized_email,
                hashed_password,
                account_type,
                company_name,
                verification_code,
                verification_expiry,
                False,
            ),
        )
        conn.commit()

        send_verification_email(normalized_email, verification_code)

        return JSONResponse(
            status_code=201,
            content={"message": "User created. Please verify your email."},
        )
    except Exception as exc:
        logger.exception("Unexpected error during registration: %s", exc)
        if conn:
            conn.rollback()
        return JSONResponse(status_code=500, content={"error": "Internal Server Error"})
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@router.post("/verify-email")
def verify_email(payload: VerifyCodeRequest):
    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT verification_code, verification_expiry, is_verified FROM users WHERE email=%s",
            (payload.email,),
        )
        row = cur.fetchone()

        if not row:
            return JSONResponse(status_code=404, content={"error": "User not found"})

        stored_code, expiry, is_verified = row

        if is_verified:
            return JSONResponse(
                status_code=200,
                content={"message": "Account verified successfully"},
            )

        if stored_code != payload.code:
            return JSONResponse(status_code=400, content={"error": "Invalid code"})

        if not expiry:
            return JSONResponse(status_code=400, content={"error": "Code expired"})

        expiry_naive = expiry
        if hasattr(expiry_naive, "tzinfo") and expiry_naive.tzinfo is not None:
            expiry_naive = expiry_naive.astimezone(timezone.utc).replace(tzinfo=None)

        if expiry_naive < datetime.utcnow():
            return JSONResponse(status_code=400, content={"error": "Code expired"})

        cur.execute(
            """
            UPDATE users
            SET is_verified = TRUE,
                verification_code = NULL,
                verification_expiry = NULL
            WHERE email = %s
            """,
            (payload.email,),
        )
        conn.commit()

        return JSONResponse(
            status_code=200,
            content={"message": "Account verified successfully"},
        )
    except Exception as exc:
        logger.exception("Unexpected error during email verification: %s", exc)
        if conn:
            conn.rollback()
        return JSONResponse(status_code=500, content={"error": "Internal Server Error"})
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@router.post("/login")
def login(user: UserLogin):
    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, hashed_password FROM users WHERE email=%s",
            (user.email,),
        )
        row = cur.fetchone()

        if not row:
            return JSONResponse(
                status_code=400,
                media_type="application/json",
                content={"message": "Invalid credentials"},
            )

        user_id, email, hashed_password = row

        if not verify_password(user.password, hashed_password):
            return JSONResponse(
                status_code=400,
                media_type="application/json",
                content={"message": "Invalid credentials"},
            )

        expiration = datetime.now(timezone.utc) + timedelta(hours=8)
        payload = {"sub": email, "user_id": user_id, "exp": expiration}
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "message": "Login successful",
                "token": token,
                "user": {"id": user_id, "email": email},
            },
        )
    except Exception as exc:
        logger.exception("Unexpected error during login: %s", exc)
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={"error": "Internal Server Error"},
        )
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@router.put("/update-password")
def update_password(
    payload: UpdatePasswordRequest, authorization: str = Header(default=None)
):
    if not authorization or not authorization.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})

    token = authorization.split("Bearer ", 1)[1].strip()
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded_token.get("user_id")
        if not user_id:
            raise ValueError("Missing user_id in token")
    except jwt.ExpiredSignatureError:
        return JSONResponse(status_code=401, content={"error": "Token expired"})
    except (InvalidTokenError, ValueError):
        return JSONResponse(status_code=401, content={"error": "Invalid token"})

    if payload.new_password != payload.confirm_password:
        return JSONResponse(
            status_code=400, content={"error": "Passwords do not match"}
        )

    conn = None
    cur = None
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT hashed_password FROM users WHERE id=%s", (user_id,))
        row = cur.fetchone()

        if not row or not row[0]:
            return JSONResponse(status_code=404, content={"error": "User not found"})

        if not verify_password(payload.current_password, row[0]):
            return JSONResponse(
                status_code=400,
                content={"error": "Current password is incorrect"},
            )

        new_hashed_password = get_password_hash(payload.new_password)
        cur.execute(
            "UPDATE users SET hashed_password=%s WHERE id=%s",
            (new_hashed_password, user_id),
        )
        conn.commit()

        return JSONResponse(status_code=200, content={"message": "Password updated"})
    except Exception as exc:
        logger.exception("Unexpected error during password update: %s", exc)
        if conn:
            conn.rollback()
        return JSONResponse(status_code=500, content={"error": "Internal Server Error"})
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@router.get("/google/login")
async def google_login(request: Request):
    if not GOOGLE_OAUTH_ENABLED:
        logger.error("Attempted Google login without configured credentials")
        return JSONResponse(
            status_code=400, content={"error": "Google authentication failed"}
        )

    app_origin_param = request.query_params.get("app_origin")
    if not app_origin_param:
        logger.error("Missing app_origin in Google login request")
        return JSONResponse(status_code=400, content={"error": "Missing app_origin"})

    state_token = token_urlsafe(32)
    request.session["oauth_state"] = state_token
    request.session["app_origin"] = app_origin_param

    redirect_uri = "https://meetmymetrics-api.azurewebsites.net/auth/google/callback"
    logger.info("Using Google redirect_uri: %s", redirect_uri)
    return await oauth.google.authorize_redirect(
        request, redirect_uri, state=state_token
    )


@router.get("/google/callback")
async def google_callback(request: Request):
    conn = None
    cur = None
    if not GOOGLE_OAUTH_ENABLED:
        logger.error("Attempted Google callback without configured credentials")
        return JSONResponse(
            status_code=400, content={"error": "Google authentication failed"}
        )

    app_origin_param = request.session.pop("app_origin", None)
    if not app_origin_param:
        logger.error("Missing app_origin in Google callback session")
        request.session.pop("oauth_state", None)
        error_html = _build_post_message_html(
            {
                "type": "GOOGLE_AUTH_ERROR",
                "error": "Google authentication failed",
            },
            "Google authentication failed. You can close this window.",
            "*",
        )
        return HTMLResponse(status_code=400, content=error_html)

    try:
        app_origin = _validate_app_origin(app_origin_param)
    except ValueError as exc:
        logger.warning("Invalid app_origin provided: %s", exc)
        request.session.pop("oauth_state", None)
        error_html = """
        <!DOCTYPE html>
        <html lang=\"en\">
        <head>
            <meta charset=\"UTF-8\" />
            <title>Authentication Error</title>
        </head>
        <body>
            <p>Google authentication failed. You can close this window.</p>
        </body>
        </html>
        """
        return HTMLResponse(status_code=400, content=error_html)

    try:
        request_state = request.query_params.get("state")
        session_state = request.session.pop("oauth_state", None)

        if not request_state or not session_state or request_state != session_state:
            logger.warning("Invalid OAuth state received during Google callback")
            error_html = _build_post_message_html(
                {
                    "type": "GOOGLE_AUTH_ERROR",
                    "error": "Google authentication failed",
                },
                "Google authentication failed. You can close this window.",
                app_origin,
            )
            return HTMLResponse(status_code=400, content=error_html)

        token = await oauth.google.authorize_access_token(request)
        user_info = token.get("userinfo")

        if not user_info:
            user_info = await oauth.google.parse_id_token(request, token)

        email = (user_info or {}).get("email") if user_info else None
        name = (user_info or {}).get("name") if user_info else None

        if not email:
            raise ValueError("Email not provided by Google")

        if not name:
            name = email.split("@")[0]

        conn = get_connection()
        cur = conn.cursor()

        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        db_user = cur.fetchone()

        if db_user:
            user_id = db_user[0]
        else:
            cur.execute(
                "INSERT INTO users (email, name, hashed_password) VALUES (%s, %s, %s) RETURNING id",
                (email, name, None),
            )
            user_id = cur.fetchone()[0]
            conn.commit()

        access_token = create_access_token({"sub": str(user_id), "email": email})

        issued_at = datetime.utcnow()
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            ip = forwarded_for.split(",")[0].strip()
        elif request.client:
            ip = request.client.host
        else:
            ip = None
        user_agent = request.headers.get("user-agent")

        cur.execute(
            """
            INSERT INTO user_sessions (
                user_id,
                login_provider,
                issued_at,
                ip,
                user_agent
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_id, "google", issued_at, ip, user_agent),
        )
        conn.commit()

        logger.info("Sending Google authentication token to opener via postMessage")

        user_payload = {"email": email, "name": name}
        payload = {
            "type": "GOOGLE_AUTH_SUCCESS",
            "token": access_token,
            "user": user_payload,
            "state": request_state,
        }

        html_content = _build_post_message_html(
            payload,
            "Authentication successful. You can close this window.",
            app_origin,
        )

        return HTMLResponse(content=html_content)
    except (OAuthError, ValueError, KeyError) as exc:
        logger.warning("Google authentication error: %s", exc)
        if conn:
            conn.rollback()
        error_html = _build_post_message_html(
            {
                "type": "GOOGLE_AUTH_ERROR",
                "error": "Google authentication failed",
            },
            "Google authentication failed. You can close this window.",
            app_origin,
        )
        return HTMLResponse(status_code=400, content=error_html)
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected error during Google callback: %s", exc)
        if conn:
            conn.rollback()
        error_html = _build_post_message_html(
            {
                "type": "GOOGLE_AUTH_ERROR",
                "error": "Google authentication failed",
            },
            "Google authentication failed. You can close this window.",
            app_origin,
        )
        return HTMLResponse(status_code=400, content=error_html)
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@router.post("/login")
def login(user: UserLogin):
    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT hashed_password FROM users WHERE email=%s",
            (user.email,),
        )
        db_user = cur.fetchone()

        if not db_user:
            return JSONResponse(
                status_code=400, content={"error": "Invalid credentials"}
            )

        if not verify_password(user.password, db_user[0]):
            return JSONResponse(
                status_code=400, content={"error": "Invalid credentials"}
            )

        return JSONResponse(status_code=200, content={"message": "Login successful"})
    except Exception:
        return JSONResponse(status_code=500, content={"error": "Internal Server Error"})
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
