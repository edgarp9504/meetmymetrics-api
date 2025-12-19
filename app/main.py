from fastapi import FastAPI # pyright: ignore[reportMissingImports]
from fastapi.middleware.cors import CORSMiddleware # pyright: ignore[reportMissingImports]
from starlette.middleware.sessions import SessionMiddleware # pyright: ignore[reportMissingImports]
import os

from app.auth.router import router as auth_router
from app.oauth.router import router as oauth_router, debug_router
from app.ad_accounts import router as ad_accounts_router
from app.accounts.router import router as accounts_router

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
    raise RuntimeError("SESSION_SECRET_KEY must be set")

env = os.getenv("ENV", "dev").lower()
backend_url = os.getenv("BACKEND_URL", "")
https_only = not (env in {"dev", "local"} or backend_url.startswith("http://localhost"))

app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret_key,
    session_cookie="meetmymetrics_session",
    max_age=3600,
    same_site="lax",
    https_only=https_only,
)

app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(oauth_router, tags=["OAuth"])
app.include_router(debug_router, tags=["OAuth Debug"])
app.include_router(ad_accounts_router, tags=["Ad Accounts"])
app.include_router(accounts_router, tags=["Accounts"])
