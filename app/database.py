"""Database initialization and connection management for CampusVault.

Uses SQLite with WAL mode, foreign keys enabled, and row factory.
Creates all 10 schema tables and seeds initial role definitions.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Union
from app.config import get_settings

DEFAULT_ROLES_PERMISSIONS = {
    "student": [
        "marks:read_own",
        "documents:download",
    ],
    "faculty": [
        "marks:read_own",
        "marks:read_assigned",
        "marks:write_assigned",
        "documents:download",
        "documents:upload",
        "readings:read",
    ],
    "admin": [
        "marks:read_own",
        "marks:read_assigned",
        "marks:write_assigned",
        "documents:download",
        "documents:upload",
        "users:manage",
        "audit:read",
        "keys:manage",
        "readings:read",
    ],
}

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS roles (
    name TEXT PRIMARY KEY,
    permissions TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL REFERENCES roles(name),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    recovery_token_hash TEXT,
    recovery_token_expiry TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    changed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS marks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT NOT NULL REFERENCES users(id),
    faculty_id TEXT NOT NULL REFERENCES users(id),
    course_code TEXT NOT NULL,
    course_name TEXT NOT NULL,
    score INTEGER NOT NULL,
    semester TEXT NOT NULL,
    entered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS crypto_keys (
    id TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    state TEXT NOT NULL,
    encrypted_key_material BLOB NOT NULL,
    key_nonce BLOB NOT NULL,
    public_key_material BLOB,
    created_at TEXT NOT NULL,
    rotated_at TEXT,
    revoked_at TEXT,
    replaced_by TEXT REFERENCES crypto_keys(id),
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    uploader_id TEXT NOT NULL REFERENCES users(id),
    encryption_key_id TEXT NOT NULL REFERENCES crypto_keys(id),
    file_path TEXT NOT NULL,
    signature_path TEXT NOT NULL,
    signing_key_id TEXT NOT NULL REFERENCES crypto_keys(id),
    content_hash TEXT NOT NULL,
    uploaded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nonce_cache (
    nonce TEXT PRIMARY KEY,
    received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sensor_readings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id TEXT NOT NULL,
    temperature REAL NOT NULL,
    humidity REAL NOT NULL,
    timestamp TEXT NOT NULL,
    received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    identity TEXT NOT NULL,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_marks_student_id ON marks(student_id);
CREATE INDEX IF NOT EXISTS idx_marks_faculty_id ON marks(faculty_id);
CREATE INDEX IF NOT EXISTS idx_documents_uploader ON documents(uploader_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_crypto_keys_purpose_state ON crypto_keys(purpose, state);
"""


def get_db_path(db_path: Union[str, Path, None] = None) -> Path:
    """Resolve database path."""
    if db_path is not None:
        return Path(db_path)
    return get_settings().db_path


def get_db_connection(db_path: Union[str, Path, None] = None) -> sqlite3.Connection:
    """Create and return a configured sqlite3 connection."""
    target_path = get_db_path(db_path)
    # Ensure parent dir exists if writing to file
    if str(target_path) != ":memory:":
        target_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        str(target_path),
        check_same_thread=False,
        timeout=30.0
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    if str(target_path) != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL;")
    return conn


@contextmanager
def db_session(db_path: Union[str, Path, None] = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for database operations with automatic commit/rollback."""
    conn = get_db_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Union[str, Path, None] = None) -> None:
    """Initialize database tables and seed roles."""
    with db_session(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        # Seed default roles if not present
        for role_name, perms in DEFAULT_ROLES_PERMISSIONS.items():
            conn.execute(
                """
                INSERT OR IGNORE INTO roles (name, permissions)
                VALUES (?, ?)
                """,
                (role_name, json.dumps(perms))
            )
