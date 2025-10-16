from pydantic import BaseModel

class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str
    name: str

class Token(BaseModel):
    access_token: str
    token_type: str
