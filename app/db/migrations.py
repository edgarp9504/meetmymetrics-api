"""Utilities for ensuring database schema related to account management exists."""

from __future__ import annotations

from contextlib import contextmanager

from psycopg2.extensions import connection as PGConnection


@contextmanager
def _cursor(conn: PGConnection):
    cur = conn.cursor()
    try:
        yield cur
    finally:
        cur.close()


def ensure_account_schema(conn: PGConnection) -> None:
    """Create the multi-account tables if they do not exist."""

    with _cursor(conn) as cur:
        cur.execute(
            """
            CREATE TYPE IF NOT EXISTS plan_type AS ENUM ('free', 'pro', 'business')
            """
        )

        cur.execute(
            """
            CREATE TYPE IF NOT EXISTS invitation_status AS ENUM (
                'pending',
                'accepted',
                'expired',
                'revoked'
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id SERIAL PRIMARY KEY,
                owner_user_id INTEGER NOT NULL UNIQUE
                    REFERENCES users(id) ON DELETE CASCADE,
                plan_type plan_type NOT NULL DEFAULT 'free',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS account_members (
                id SERIAL PRIMARY KEY,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                role VARCHAR(32) NOT NULL,
                invited_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(account_id, user_id)
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS account_invitations (
                id SERIAL PRIMARY KEY,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                email TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                status invitation_status NOT NULL DEFAULT 'pending',
                expires_at TIMESTAMPTZ NOT NULL,
                invited_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                accepted_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_account_invitations_account_email
            ON account_invitations (account_id, lower(email))
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_account_members_account
            ON account_members (account_id)
            """
        )


__all__ = ["ensure_account_schema"]

