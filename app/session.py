"""Session management and CSRF token generation for CampusVault.

Implements:
- Cryptographically random session tokens (32 bytes urlsafe)
- 30-minute server-side session expiration
- Explicit session invalidation on logout
- HMAC-based CSRF token generation and constant-time validation
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import secrets
from pathlib import Path
from typing import Optional, Union

from app.database import db_session, get_db_connection

SESSION_LIFETIME_MINUTES = 30


def create_session(user_id: str, db_path: Union[str, Path, None] = None) -> str:
    """Create a new authenticated session for user and return the session token."""
    session_id = secrets.token_urlsafe(32)
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = (now + datetime.timedelta(minutes=SESSION_LIFETIME_MINUTES)).isoformat()
    now_iso = now.isoformat()

    with db_session(db_path) as conn:
        conn.execute(
            """
            INSERT INTO sessions (id, user_id, created_at, expires_at, is_active)
            VALUES (?, ?, ?, ?, 1)
            """,
            (session_id, user_id, now_iso, expires_at),
        )
    return session_id


def validate_session(session_id: str, db_path: Union[str, Path, None] = None) -> Optional[dict]:
    """Validate a session token.

    Returns user and session info if active and non-expired, or None otherwise.
    """
    if not session_id:
        return None

    now_dt = datetime.datetime.now(datetime.timezone.utc)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            """
            SELECT s.id AS session_id, s.user_id, s.expires_at, s.is_active,
                   u.username, u.email, u.role
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = ?
            """,
            (session_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        if row["is_active"] != 1:
            return None

        expires_dt = datetime.datetime.fromisoformat(row["expires_at"])
        if now_dt >= expires_dt:
            # Expired session
            return None

        return dict(row)
    finally:
        conn.close()


def terminate_session(session_id: str, db_path: Union[str, Path, None] = None) -> None:
    """Explicitly deactivate a session on logout."""
    if not session_id:
        return
    with db_session(db_path) as conn:
        conn.execute(
            "UPDATE sessions SET is_active = 0 WHERE id = ?",
            (session_id,),
        )


def generate_csrf_token(session_id: str, secret: str) -> str:
    """Derive an HMAC-SHA256 CSRF token cryptographically bound to the session."""
    return hmac.new(
        secret.encode("utf-8"),
        session_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def validate_csrf_token(token: str, session_id: str, secret: str) -> bool:
    """Validate CSRF token using constant-time comparison."""
    if not token or not session_id:
        return False
    expected = generate_csrf_token(session_id, secret)
    return hmac.compare_digest(expected, token)
