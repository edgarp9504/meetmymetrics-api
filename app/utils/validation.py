"""Validation utilities for user input."""

from __future__ import annotations

import re

from disposable_email_domains import blocklist
from email_validator import EmailNotValidError, validate_email

GENERIC_TEST_EMAILS = {
    "test@test.com",
    "example@example.com",
    "admin@admin.com",
    "correo@correo.com",
}

LOW_REPUTATION_DOMAINS = {
    "mailinator.com",
    "tempmail.com",
    "tempmail.net",
    "10minutemail.com",
    "guerrillamail.com",
    "trashmail.com",
    "fakeinbox.com",
    "sharklasers.com",
}

SUSPICIOUS_KEYWORD_PATTERN = re.compile(r"(bot|spam|fake|test|demo)", re.IGNORECASE)
SUSPICIOUS_DOMAIN_PATTERN = re.compile(r"(bot|spam|fake|test|demo)", re.IGNORECASE)
SPECIAL_CHAR_PATTERN = re.compile(r"[!@#$%^&*]")


def normalize_email(email: str) -> str:
    """Normalize and basic-validate an email address string."""
    if email is None:
        raise ValueError("Email address is required")

    cleaned = email.strip()
    if not cleaned:
        raise ValueError("Email address is required")

    if " " in cleaned:
        raise ValueError("Email addresses cannot contain spaces")

    return cleaned.lower()


def validate_email_address(email: str) -> str:
    """Validate email format and return the normalized address."""
    normalized = normalize_email(email)

    if "@" not in normalized:
        raise ValueError("Email must contain '@'")

    try:
        # Do not require MX record to avoid blocking legitimate domains without DNS entries.
        result = validate_email(normalized, check_deliverability=False)
    except EmailNotValidError as exc:
        raise ValueError(str(exc)) from exc

    normalized = result.normalized
    domain = normalized.split("@", 1)[1]

    if domain in LOW_REPUTATION_DOMAINS:
        raise ValueError("Disposable email domains are not allowed")

    if domain in blocklist:
        raise ValueError("Disposable email domains are not allowed")

    return normalized


def is_suspicious_email(email: str) -> bool:
    """Return True when the email looks automated or suspicious."""
    try:
        normalized = normalize_email(email)
    except ValueError:
        return True

    if normalized in GENERIC_TEST_EMAILS:
        return True

    if "@" not in normalized:
        return True

    local_part, domain = normalized.split("@", 1)

    if SUSPICIOUS_KEYWORD_PATTERN.search(local_part):
        return True

    if SUSPICIOUS_DOMAIN_PATTERN.search(domain):
        return True

    domain_tokens = domain.replace("-", ".").split(".")
    if any(token in {"mailinator", "tempmail", "guerrillamail", "10minutemail"} for token in domain_tokens):
        return True

    if domain in LOW_REPUTATION_DOMAINS or domain in blocklist:
        return True

    return False


def validate_password_strength(password: str) -> bool:
    """Return True when the password satisfies complexity requirements."""
    if password is None:
        return False

    if len(password) < 8:
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"\d", password):
        return False

    if not SPECIAL_CHAR_PATTERN.search(password):
        return False

    return True


__all__ = [
    "is_suspicious_email",
    "normalize_email",
    "validate_email_address",
    "validate_password_strength",
]
