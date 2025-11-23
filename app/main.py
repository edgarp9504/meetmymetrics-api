import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.auth.routes import router as auth_router
from app.core.config import settings
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

session_secret_key = os.getenv("SESSION_SECRET_KEY", settings.secret_key)

app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret_key,
    session_cookie=settings.session_cookie_name,
    same_site=settings.session_cookie_samesite,
    https_only=settings.session_cookie_secure,
    domain=settings.session_cookie_domain,
    max_age=86400,
)

app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(oauth.router)
app.include_router(oauth.debug_router)
app.include_router(ad_accounts.router)
app.include_router(accounts.router)
