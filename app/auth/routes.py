import logging
import re

from authlib.integrations.starlette_client import OAuth, OAuthError
from disposable_email_domains import blocklist
from email_validator import EmailNotValidError, validate_email
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.auth.schemas import UserLogin, UserRegister
from app.core.config import settings
from app.core.security import create_access_token
from app.db.connection import get_connection
from app.utils.hashing import get_password_hash, verify_password

router = APIRouter()
logger = logging.getLogger(__name__)

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

    raw_email = (user.email or "").strip()
    name = (user.name or "").strip()
    password = user.password or ""

    email_pattern = re.compile(r"^[^@\s]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")
    password_pattern = re.compile(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$"
    )

    if not raw_email or not email_pattern.match(raw_email):
        return JSONResponse(
            status_code=400, content={"error": "Invalid email format"}
        )

    try:
        validated_email = validate_email(raw_email, check_deliverability=False)
        email = validated_email.email
        domain = validated_email.domain.lower()
    except EmailNotValidError as exc:
        logger.warning("Invalid email format provided: %s", exc)
        return JSONResponse(
            status_code=400, content={"error": "Invalid email format"}
        )

    if domain in blocklist:
        return JSONResponse(
            status_code=400,
            content={"error": "Disposable or fake email not allowed"},
        )

    try:
        validate_email(email, check_deliverability=True)
    except EmailNotValidError as exc:
        logger.warning("Email domain not reachable: %s", exc)
        return JSONResponse(
            status_code=400, content={"error": "Email domain not reachable"}
        )

    if not password_pattern.match(password):
        return JSONResponse(
            status_code=400,
            content={"error": "Password does not meet security requirements"},
        )

    if not name:
        return JSONResponse(status_code=400, content={"error": "Name is required"})

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("SELECT 1 FROM users WHERE email=%s", (email,))
        if cur.fetchone():
            return JSONResponse(status_code=400, content={"error": "Email already registered"})

        hashed_pw = get_password_hash(password)
        cur.execute(
            "INSERT INTO users (email, hashed_password, name) VALUES (%s, %s, %s)",
            (email, hashed_pw, name),
        )
        conn.commit()

        return {"message": "User registered successfully"}
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

@router.get("/google/login")
async def google_login(request: Request):
    if not GOOGLE_OAUTH_ENABLED:
        logger.error("Attempted Google login without configured credentials")
        return JSONResponse(
            status_code=400, content={"error": "Google authentication failed"}
        )

    redirect_uri = request.url_for("google_callback")
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

        return JSONResponse(
            status_code=200,
            content={"access_token": access_token, "token_type": "bearer"},
        )
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
