from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.auth.routes import router as auth_router

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

app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
