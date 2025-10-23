import logging
import random
from datetime import datetime, timedelta, timezone

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
from app.utils.email import send_verification_email

router = APIRouter()
logger = logging.getLogger(__name__)

SECRET_KEY = "super_secret_key"

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


@router.post("/register")
def register(user: UserRegister):
    conn = None
    cur = None

    verification_code = f"{random.randint(100000, 999999)}"
    verification_expiry = datetime.utcnow() + timedelta(minutes=10)

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("SELECT 1 FROM users WHERE email=%s", (user.email,))
        if cur.fetchone():
            return JSONResponse(
                status_code=400,
                content={"error": "Email already registered"},
            )

        hashed_password = get_password_hash(user.password)
        cur.execute(
            """
            INSERT INTO users (
                email,
                hashed_password,
                verification_code,
                verification_expiry,
                is_verified
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                user.email,
                hashed_password,
                verification_code,
                verification_expiry,
                False,
            ),
        )
        conn.commit()

        send_verification_email(user.email, verification_code)

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

    redirect_uri = "https://meetmymetrics-api.azurewebsites.net/auth/google/callback"
    logger.info("Using Google redirect_uri: %s", redirect_uri)
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/google/callback")
async def google_callback(request: Request):
    conn = None
    cur = None

    if not GOOGLE_OAUTH_ENABLED:
        logger.error("Attempted Google callback without configured credentials")
        return JSONResponse(
            status_code=400, content={"error": "Google authentication failed"}
        )

    try:
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
        logger.info("Sending Google authentication token to opener via postMessage")

        html_content = f"""
        <!DOCTYPE html>
        <html lang=\"en\">
        <head>
            <meta charset=\"UTF-8\" />
            <title>Authentication Successful</title>
        </head>
        <body>
            <script>
                (function () {{
                    var token = {access_token!r};
                    if (window.opener && typeof window.opener.postMessage === 'function') {{
                        window.opener.postMessage({{ type: 'google-auth', token: token }}, '*');
                    }}
                    window.close();
                }})();
            </script>
            <p>Authentication successful. You can close this window.</p>
        </body>
        </html>
        """

        return HTMLResponse(content=html_content)
    except (OAuthError, ValueError, KeyError) as exc:
        logger.warning("Google authentication error: %s", exc)
        if conn:
            conn.rollback()
        return JSONResponse(
            status_code=400, content={"error": "Google authentication failed"}
        )
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected error during Google callback: %s", exc)
        if conn:
            conn.rollback()
        return JSONResponse(
            status_code=400, content={"error": "Google authentication failed"}
        )
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
