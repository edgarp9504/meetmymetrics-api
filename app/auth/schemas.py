import re
from typing import Literal, Optional

from pydantic import BaseModel, Field, root_validator, validator

class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str
    account_type: Literal["personal", "agencia"]
    company_name: Optional[str] = None

    @validator("first_name", "last_name")
    def validate_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("El nombre no puede estar vacío.")

        if len(cleaned) > 100:
            raise ValueError("El nombre debe tener máximo 100 caracteres.")

        if not re.fullmatch(r"[A-Za-zÁÉÍÓÚÜÑáéíóúüñ' -]+", cleaned):
            raise ValueError("El nombre solo puede contener letras, espacios, apóstrofes o guiones.")

        return cleaned

    @validator("company_name")
    def validate_company_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value

        cleaned = value.strip()
        if not cleaned:
            raise ValueError("El nombre de la empresa no puede estar vacío.")

        if len(cleaned) > 150:
            raise ValueError("El nombre de la empresa debe tener máximo 150 caracteres.")

        return cleaned

    @validator("account_type", pre=True)
    def normalize_account_type(cls, value: str) -> str:
        if isinstance(value, str):
            value = value.strip().lower()
        return value

    @root_validator
    def ensure_company_for_agency(cls, values: dict) -> dict:
        account_type = values.get("account_type")
        company_name = values.get("company_name")

        if account_type == "agencia" and not company_name:
            raise ValueError("company_name es obligatorio para cuentas de tipo 'agencia'.")

        if account_type == "personal":
            values["company_name"] = None

        return values


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
