from pydantic import BaseModel, Field

class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str


class VerifyCodeRequest(BaseModel):
    email: str
    code: str

class UpdatePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str


class Token(BaseModel):
    access_token: str
    token_type: str

class UserCreate(BaseModel):
    email: str
    password: str = Field(..., min_length=8, max_length=128)
