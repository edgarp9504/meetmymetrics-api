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
    """Ensure the schema for account and invitation management exists."""

    with _cursor(conn) as cur:
        # Tabla: accounts
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS public.accounts (
                id SERIAL PRIMARY KEY,
                owner_user_id INTEGER NOT NULL UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
                name VARCHAR(150) NOT NULL,
                plan_type VARCHAR(20) NOT NULL DEFAULT 'free' CHECK (plan_type IN ('free','pro','business')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        # Tabla: account_members
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS public.account_members (
                id SERIAL PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
                role VARCHAR(20) NOT NULL DEFAULT 'member' CHECK (role IN ('owner','admin','member')),
                invited_by_user_id INTEGER REFERENCES public.users(id) ON DELETE SET NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (account_id, user_id)
            );
            """
        )

        # Tabla: account_invitations
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS public.account_invitations (
                id SERIAL PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
                invited_email VARCHAR(100) NOT NULL,
                invited_first_name VARCHAR(50),
                invited_last_name VARCHAR(50),
                invited_by_user_id INTEGER NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
                token VARCHAR(128) NOT NULL UNIQUE,
                status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','revoked','expired')),
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (account_id, invited_email)
            );
            """
        )

        # Índices adicionales
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_account_members_account
            ON public.account_members (account_id);
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_account_invitations_account_email
            ON public.account_invitations (account_id, lower(invited_email));
            """
        )


__all__ = ["ensure_account_schema"]

