from fastapi import FastAPI
from app.auth.routes import router as auth_router

app = FastAPI(title="MeetMyMetrics API")

app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
