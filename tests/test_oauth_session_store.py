import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

os.environ.setdefault("POSTGRES_CONNECTION_STRING", "sqlite://")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.oauth.session_store import (  # noqa: E402
    load_origin,
    load_state,
    store_origin,
    store_state,
    validate_state,
)
from app.oauth.service import normalize_provider  # noqa: E402


class DummyRequest(SimpleNamespace):
    def __init__(self):
        super().__init__(session={})


def test_store_and_validate_state_per_provider():
    request = DummyRequest()
    store_state(request, "meta", "state_meta")
    store_state(request, "google", "state_google")

    assert load_state(request, "meta") == "state_meta"
    assert load_state(request, "google") == "state_google"

    validate_state(request, "meta", "state_meta")
    assert load_state(request, "meta") is None
    assert load_state(request, "google") == "state_google"

    validate_state(request, "google", "state_google")
    assert request.session == {}


def test_store_and_load_origin_cleanup():
    request = DummyRequest()
    store_origin(request, "meta", "https://app.example")
    store_origin(request, "google", "https://app.example/google")

    assert load_origin(request, "meta") == "https://app.example"
    assert "google" in request.session.get("oauth_origin", {})

    assert load_origin(request, "google") == "https://app.example/google"
    assert "oauth_origin" not in request.session


def test_validate_state_rejects_invalid():
    request = DummyRequest()
    store_state(request, "meta", "state_meta")

    with pytest.raises(HTTPException):
        validate_state(request, "meta", "wrong_state")


@pytest.mark.parametrize("alias,expected", [("google_ads", "google"), ("Google", "google")])
def test_normalize_provider_alias(alias: str, expected: str):
    assert normalize_provider(alias) == expected


@pytest.mark.parametrize("provider", ["unknown", "twitter"])
def test_normalize_provider_rejects_unknown(provider: str):
    with pytest.raises(HTTPException):
        normalize_provider(provider)
