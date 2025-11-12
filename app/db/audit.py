"""Helpers for recording audit events in the database."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Optional

from psycopg2 import DatabaseError
from psycopg2.extensions import connection as PGConnection

from app.db.connection import get_connection


@contextmanager
def _ensure_connection(conn: Optional[PGConnection]):
    owned_conn = False
    if conn is None:
        conn = get_connection()
        owned_conn = True
    try:
        yield conn
    finally:
        if owned_conn and conn:
            conn.close()


def log_action(
    conn: PGConnection,
    user_id: Optional[int],
    account_id: Optional[int],
    action_type: str,
    description: Optional[str],
    ip_address: Optional[str] = None,
) -> None:
    """Persist a new entry in the audit_log table."""

    if not action_type:
        raise ValueError("action_type is required for audit logging")

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO audit_log (user_id, account_id, action_type, description, ip_address)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_id, account_id, action_type, description, ip_address),
        )
    conn.commit()


def safe_log_action(
    user_id: Optional[int],
    account_id: Optional[int],
    action_type: str,
    description: Optional[str],
    ip_address: Optional[str] = None,
    conn: Optional[PGConnection] = None,
) -> None:
    """Record an audit event while swallowing database errors.

    This helper is useful for situations where audit logging should not block
    the main execution flow (e.g. after sending a notification email).
    """

    try:
        with _ensure_connection(conn) as ensured_conn:
            log_action(ensured_conn, user_id, account_id, action_type, description, ip_address)
    except (DatabaseError, ValueError) as exc:
        print(f"⚠️ No se pudo registrar el evento de auditoría '{action_type}': {exc}")
