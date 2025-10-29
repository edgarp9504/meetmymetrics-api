import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.auth.schemas import UserRegister


def test_agency_requires_company_name() -> None:
    with pytest.raises(ValidationError) as exc_info:
        UserRegister(
            first_name="Agente",
            last_name="García",
            email="agente@example.com",
            password="secreto123",
            account_type="agencia",
        )

    assert "company_name es obligatorio" in str(exc_info.value)


def test_personal_allows_missing_company_name() -> None:
    user = UserRegister(
        first_name="Ana",
        last_name="Pérez",
        email="ana@example.com",
        password="secreto123",
        account_type="personal",
    )

    assert user.company_name is None


def test_personal_removes_provided_company_name() -> None:
    user = UserRegister(
        first_name="Juan",
        last_name="López",
        email="juan@example.com",
        password="secreto123",
        account_type="personal",
        company_name="Empresa Ficticia",
    )

    assert user.company_name is None
