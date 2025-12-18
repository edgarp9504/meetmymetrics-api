import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.auth.router import router as auth_router
from routers import accounts, ad_accounts, oauth

app = FastAPI(title="MeetMyMetrics API")

origins = [
    "http://localhost:8080",
    "https://localhost:8080",
    "https://meetmymetrics.vercel.app",
    "https://meetmymetrics.net",
    "https://lemon-grass-075d5c610.3.azurestaticapps.net",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

session_secret_key = os.getenv("SESSION_SECRET_KEY")
if not session_secret_key:
    raise RuntimeError("SESSION_SECRET_KEY must be set for session management")

required_env_vars = [
    "GOOGLE_ADS_CLIENT_ID",
    "GOOGLE_ADS_CLIENT_SECRET",
    "GOOGLE_ADS_REDIRECT_URI",
    "SESSION_SECRET_KEY",
]
missing_env_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_env_vars:
    missing = ", ".join(missing_env_vars)
    raise RuntimeError(f"Missing required environment variables: {missing}")

https_only = True
env = os.getenv("ENV", "dev").lower()
backend_url = os.getenv("BACKEND_URL", "")
if env in {"dev", "local"} or backend_url.startswith("http://localhost"):
    https_only = False

app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret_key,
    session_cookie="meetmymetrics_session",
    max_age=3600,
    same_site="lax",
    https_only=https_only,
)

app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(oauth.router)
app.include_router(oauth.debug_router)
app.include_router(ad_accounts.router)
app.include_router(accounts.router)
