import logging
from typing import Optional

from fastapi import HTTPException, Request, status # pyright: ignore[reportMissingImports]

STATE_SESSION_KEY = "oauth_state_by_provider"
ORIGIN_SESSION_KEY = "oauth_origin"

logger = logging.getLogger(__name__)


def store_state(request: Request, provider: str, state: str) -> None:
    logger.info(
        "[OAuth] Storing state for provider=%s | state_len=%s | session_keys=%s",
        provider,
        len(state),
        list(request.session.keys()),
    )
    state_container = dict(request.session.get(STATE_SESSION_KEY, {}))
    state_container[provider] = state
    request.session[STATE_SESSION_KEY] = state_container


def load_state(request: Request, provider: str) -> Optional[str]:
    state_container = dict(request.session.get(STATE_SESSION_KEY, {}))
    return state_container.get(provider)


def validate_state(request: Request, provider: str, incoming_state: str) -> None:
    expected_state = load_state(request, provider)
    logger.info(
        "[OAuth] Validating state | provider=%s | incoming_len=%s | expected_present=%s",
        provider,
        len(incoming_state) if incoming_state else 0,
        expected_state is not None,
    )

    if not expected_state or expected_state != incoming_state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OAuth state received",
        )

    state_container = dict(request.session.get(STATE_SESSION_KEY, {}))
    state_container.pop(provider, None)
    if state_container:
        request.session[STATE_SESSION_KEY] = state_container
    else:
        request.session.pop(STATE_SESSION_KEY, None)


def store_origin(request: Request, provider: str, origin: str) -> None:
    origin_container = dict(request.session.get(ORIGIN_SESSION_KEY, {}))
    origin_container[provider] = origin
    request.session[ORIGIN_SESSION_KEY] = origin_container


def load_origin(request: Request, provider: str) -> Optional[str]:
    origin_container = dict(request.session.get(ORIGIN_SESSION_KEY, {}))
    origin = origin_container.pop(provider, None)
    if origin_container:
        request.session[ORIGIN_SESSION_KEY] = origin_container
    else:
        request.session.pop(ORIGIN_SESSION_KEY, None)
    return origin
