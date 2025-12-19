from fastapi import APIRouter, Header, Request # pyright: ignore[reportMissingImports]
from fastapi.responses import RedirectResponse # pyright: ignore[reportMissingImports]

from app.auth import service
from app.auth.schemas import UpdatePasswordRequest, UserLogin, UserRegister, VerifyCodeRequest

router = APIRouter()


@router.post("/register")
def register(user: UserRegister, request: Request):
    return service.register_user(user, request)


@router.post("/verify")
@router.post("/verify-email")
@router.post("/verify_email")
def verify_email(payload: VerifyCodeRequest):
    return service.verify_email(payload)


@router.post("/login")
def login(user: UserLogin):
    return service.login(user)


@router.put("/update-password")
def update_password(payload: UpdatePasswordRequest, authorization: str = Header(default=None)):
    return service.update_password(payload, authorization)


@router.get("/google/login", response_class=RedirectResponse)
async def google_login(request: Request):
    return await service.google_login(request)


@router.get("/google/callback")
async def google_callback(request: Request):
    return await service.google_callback(request)
