"""Authentication and Password Management for CampusVault.

Implements:
- Argon2id password hashing with unique salts
- Strict password complexity enforcement
- Common password blocklist checking
- Last-3 password history enforcement
- Account lockout after 5 consecutive failed attempts (15 min window)
- Secure, time-limited password recovery
"""

from __future__ import annotations

import datetime
import re
import secrets
from pathlib import Path
from typing import Optional, Union

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

from app.database import db_session, get_db_connection
from audit.logger import AuditLogger
from audit.models import EventType, AuditResult

# Argon2id hasher configuration
# time_cost=3, memory_cost=65536 (64 MiB), parallelism=4, hash_len=32, salt_len=16
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

# Dummy hash for timing attack mitigation on non-existent users
DUMMY_HASH = ph.hash("DummyPassword123!SafeTiming")

# Top 100 common passwords blocklist
COMMON_PASSWORDS_BLOCKLIST = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
    "1234567", "dragon", "123123", "baseball", "football", "monkey", "letmein", "sunshine",
    "1234567890", "master", "welcome", "shadow", "ashley", "bailey", "charlie", "hunter",
    "pass1234", "password123", "password1", "admin123", "admin", "root", "toor", "default",
    "qwertyuiop", "trustno1", "computer", "princess", "superman", "jordan", "michael",
    "mustang", "harley", "ninja", "ranger", "secret", "server", "campusvault", "student123",
    "faculty123", "admin2026", "college123", "university1", "testing123", "iloveyou",
    "starwars", "pokemon", "matrix", "freedom", "cookie", "killer", "buster", "barbie",
    "cheesecake", "summer", "winter", "autumn", "spring", "september", "december",
    "changeit", "changeme", "temppass123", "welcome123", "access123", "database1",
    "system123", "user1234", "testing1", "sample123", "guest1234", "operator1",
    "securepass", "secure123", "campus1234", "vaultpass1", "cybersec123", "hcltech2026",
    "hcltech123", "studentpass", "facultypass", "adminpass1", "portal2026", "security123",
    "mypassword1", "password123!", "Welcome1234!", "Password123!", "Admin123456!"
}


class AuthError(Exception):
    """Base authentication error."""
    pass


class AuthenticationFailedError(AuthError):
    """Generic invalid credentials error."""
    pass


class AccountLockedError(AuthError):
    """Account locked due to consecutive failed attempts."""
    pass


class PasswordPolicyError(AuthError):
    """Password does not satisfy security policy."""
    pass


def check_password_policy(password: str) -> list[str]:
    """Check password against complexity rules and blocklist.

    Rules:
    - Min 12 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special character
    - Not in common password blocklist
    """
    violations: list[str] = []

    if len(password) < 12:
        violations.append("Password must be at least 12 characters long.")
    if not re.search(r"[A-Z]", password):
        violations.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        violations.append("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        violations.append("Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'/`~]", password):
        violations.append("Password must contain at least one special character.")

    if password.lower() in COMMON_PASSWORDS_BLOCKLIST or password in COMMON_PASSWORDS_BLOCKLIST:
        violations.append("Password is too common and appears in the disallowed blocklist.")

    return violations


def register_user(
    username: str,
    email: str,
    password: str,
    role: str = "student",
    db_path: Union[str, Path, None] = None,
    audit_logger: Optional[AuditLogger] = None,
) -> str:
    """Register a new user with Argon2id password hash."""
    audit = audit_logger or AuditLogger(db_path=db_path)

    # 1. Enforce password policy
    violations = check_password_policy(password)
    if violations:
        raise PasswordPolicyError("; ".join(violations))

    # 2. Validate role
    if role not in ("student", "faculty", "admin"):
        raise AuthError(f"Invalid role '{role}'.")

    # 3. Hash password
    password_hash = ph.hash(password)
    user_id = secrets.token_hex(16)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        with db_session(db_path) as conn:
            conn.execute(
                """
                INSERT INTO users
                (id, username, email, password_hash, role, failed_attempts, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (user_id, username, email, password_hash, role, now, now),
            )
            # Record initial password in password history
            conn.execute(
                """
                INSERT INTO password_history (user_id, password_hash, changed_at)
                VALUES (?, ?, ?)
                """,
                (user_id, password_hash, now),
            )
    except Exception as e:
        audit.log(
            event_type=EventType.AUTH.value,
            identity=username,
            action="USER_REGISTRATION_FAILED",
            result=AuditResult.FAILURE.value,
            detail=f"Registration failed: {type(e).__name__}",
        )
        raise AuthError("Registration failed. Username or email may already be in use.")

    audit.log(
        event_type=EventType.AUTH.value,
        identity=username,
        action="USER_REGISTERED",
        result=AuditResult.SUCCESS.value,
        detail=f"user_id={user_id} role={role}",
    )
    return user_id


def login_user(
    username: str,
    password: str,
    db_path: Union[str, Path, None] = None,
    audit_logger: Optional[AuditLogger] = None,
) -> dict:
    """Verify credentials, enforce account lockout, reset counter on success.

    Mitigates timing attacks by hashing dummy values when user is not found.
    """
    audit = audit_logger or AuditLogger(db_path=db_path)
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now_dt.isoformat()

    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            """
            SELECT id, username, email, password_hash, role, failed_attempts, locked_until
            FROM users
            WHERE username = ?
            """,
            (username,),
        )
        user = cursor.fetchone()
    finally:
        conn.close()

    # User does not exist -> run dummy hash comparison for constant-time defense
    if not user:
        try:
            ph.verify(DUMMY_HASH, password)
        except VerificationError:
            pass
        audit.log(
            event_type=EventType.AUTH.value,
            identity=username,
            action="LOGIN_FAILURE",
            result=AuditResult.FAILURE.value,
            detail="Invalid credentials (user_not_found)",
        )
        raise AuthenticationFailedError("Invalid username or password.")

    user_dict = dict(user)
    user_id = user_dict["id"]
    failed_attempts = user_dict["failed_attempts"]
    locked_until = user_dict["locked_until"]

    # Check if account is currently locked
    if locked_until:
        locked_dt = datetime.datetime.fromisoformat(locked_until)
        if now_dt < locked_dt:
            audit.log(
                event_type=EventType.AUTH.value,
                identity=username,
                action="LOGIN_DENIED_LOCKED",
                result=AuditResult.DENIED.value,
                detail=f"Account locked until {locked_until}",
            )
            raise AccountLockedError(
                "Account is temporarily locked due to multiple failed login attempts. Please try again later."
            )
        else:
            # Lock has expired; reset failed attempts
            failed_attempts = 0

    # Verify password with Argon2id
    try:
        ph.verify(user_dict["password_hash"], password)
    except (VerifyMismatchError, VerificationError):
        # Increment failed attempts
        new_failed = failed_attempts + 1
        new_locked_until = None
        if new_failed >= 5:
            # Lock account for 15 minutes
            new_locked_until = (now_dt + datetime.timedelta(minutes=15)).isoformat()

        with db_session(db_path) as c:
            c.execute(
                """
                UPDATE users
                SET failed_attempts = ?, locked_until = ?, updated_at = ?
                WHERE id = ?
                """,
                (new_failed, new_locked_until, now_iso, user_id),
            )

        if new_locked_until:
            audit.log(
                event_type=EventType.AUTH.value,
                identity=username,
                action="ACCOUNT_LOCKED",
                result=AuditResult.DENIED.value,
                detail=f"Lockout triggered: failed_attempts={new_failed}",
            )
            raise AccountLockedError(
                "Account is temporarily locked due to multiple failed login attempts. Please try again later."
            )

        audit.log(
            event_type=EventType.AUTH.value,
            identity=username,
            action="LOGIN_FAILURE",
            result=AuditResult.FAILURE.value,
            detail=f"failed_attempts={new_failed}",
        )
        raise AuthenticationFailedError("Invalid username or password.")

    # Successful login: reset failed attempts and lockout
    with db_session(db_path) as c:
        c.execute(
            """
            UPDATE users
            SET failed_attempts = 0, locked_until = NULL, updated_at = ?
            WHERE id = ?
            """,
            (now_iso, user_id),
        )

    audit.log(
        event_type=EventType.AUTH.value,
        identity=username,
        action="LOGIN_SUCCESS",
        result=AuditResult.SUCCESS.value,
        detail=f"user_id={user_id} role={user_dict['role']}",
    )
    return user_dict


def change_password(
    user_id: str,
    old_password: str,
    new_password: str,
    db_path: Union[str, Path, None] = None,
    audit_logger: Optional[AuditLogger] = None,
) -> None:
    """Verify old password, check policy, check last-3 history, and update password."""
    audit = audit_logger or AuditLogger(db_path=db_path)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT username, password_hash FROM users WHERE id = ?",
            (user_id,),
        )
        user = cursor.fetchone()
        if not user:
            raise AuthError("User not found.")

        # 1. Verify old password
        try:
            ph.verify(user["password_hash"], old_password)
        except VerificationError:
            audit.log(
                event_type=EventType.AUTH.value,
                identity=user["username"],
                action="PASSWORD_CHANGE_FAILED",
                result=AuditResult.FAILURE.value,
                detail="Old password verification failed",
            )
            raise AuthenticationFailedError("Current password verification failed.")

        # 2. Check new password policy
        violations = check_password_policy(new_password)
        if violations:
            raise PasswordPolicyError("; ".join(violations))

        # 3. Check password history (last 3 passwords)
        hist_cursor = conn.execute(
            """
            SELECT password_hash FROM password_history
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 3
            """,
            (user_id,),
        )
        recent_hashes = [row["password_hash"] for row in hist_cursor.fetchall()]

        for old_hash in recent_hashes:
            try:
                if ph.verify(old_hash, new_password):
                    audit.log(
                        event_type=EventType.AUTH.value,
                        identity=user["username"],
                        action="PASSWORD_CHANGE_REJECTED",
                        result=AuditResult.FAILURE.value,
                        detail="Attempted reuse of previous password in history",
                    )
                    raise PasswordPolicyError(
                        "New password cannot be any of your previous 3 passwords."
                    )
            except VerificationError:
                pass
    finally:
        conn.close()

    # 4. Hash new password and update
    new_hash = ph.hash(new_password)
    with db_session(db_path) as c:
        c.execute(
            """
            UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?
            """,
            (new_hash, now, user_id),
        )
        c.execute(
            """
            INSERT INTO password_history (user_id, password_hash, changed_at)
            VALUES (?, ?, ?)
            """,
            (user_id, new_hash, now),
        )

    audit.log(
        event_type=EventType.AUTH.value,
        identity=user["username"],
        action="PASSWORD_CHANGED",
        result=AuditResult.SUCCESS.value,
        detail=f"user_id={user_id}",
    )


def initiate_recovery(
    email: str,
    db_path: Union[str, Path, None] = None,
    audit_logger: Optional[AuditLogger] = None,
) -> str:
    """Generate a single-use, time-limited recovery token."""
    audit = audit_logger or AuditLogger(db_path=db_path)
    token = secrets.token_urlsafe(32)
    token_hash = ph.hash(token)
    expiry = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    ).isoformat()

    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT id, username FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
    finally:
        conn.close()

    if not user:
        # Prevent user enumeration by taking similar time and not revealing email existence
        audit.log(
            event_type=EventType.AUTH.value,
            identity=email,
            action="RECOVERY_INITIATED_UNKNOWN",
            result=AuditResult.SUCCESS.value,
            detail="Recovery requested for non-existent email",
        )
        return token

    with db_session(db_path) as c:
        c.execute(
            """
            UPDATE users
            SET recovery_token_hash = ?, recovery_token_expiry = ?
            WHERE id = ?
            """,
            (token_hash, expiry, user["id"]),
        )

    audit.log(
        event_type=EventType.AUTH.value,
        identity=user["username"],
        action="RECOVERY_INITIATED",
        result=AuditResult.SUCCESS.value,
        detail=f"user_id={user['id']}",
    )
    return token


def complete_recovery(
    token: str,
    new_password: str,
    db_path: Union[str, Path, None] = None,
    audit_logger: Optional[AuditLogger] = None,
) -> None:
    """Validate recovery token, enforce policy, and reset password."""
    audit = audit_logger or AuditLogger(db_path=db_path)
    violations = check_password_policy(new_password)
    if violations:
        raise PasswordPolicyError("; ".join(violations))

    now_dt = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now_dt.isoformat()

    conn = get_db_connection(db_path)
    target_user_id: Optional[str] = None
    target_username: Optional[str] = None

    try:
        cursor = conn.execute(
            """
            SELECT id, username, recovery_token_hash, recovery_token_expiry
            FROM users
            WHERE recovery_token_hash IS NOT NULL
            """
        )
        rows = cursor.fetchall()

        for row in rows:
            expiry_str = row["recovery_token_expiry"]
            if expiry_str and now_dt > datetime.datetime.fromisoformat(expiry_str):
                continue
            try:
                if ph.verify(row["recovery_token_hash"], token):
                    target_user_id = row["id"]
                    target_username = row["username"]
                    break
            except VerificationError:
                pass
    finally:
        conn.close()

    if not target_user_id:
        raise AuthError("Invalid or expired recovery token.")

    new_hash = ph.hash(new_password)
    with db_session(db_path) as c:
        c.execute(
            """
            UPDATE users
            SET password_hash = ?, recovery_token_hash = NULL, recovery_token_expiry = NULL,
                failed_attempts = 0, locked_until = NULL, updated_at = ?
            WHERE id = ?
            """,
            (new_hash, now_iso, target_user_id),
        )
        c.execute(
            """
            INSERT INTO password_history (user_id, password_hash, changed_at)
            VALUES (?, ?, ?)
            """,
            (target_user_id, new_hash, now_iso),
        )

    audit.log(
        event_type=EventType.AUTH.value,
        identity=target_username or "user",
        action="RECOVERY_COMPLETED",
        result=AuditResult.SUCCESS.value,
        detail=f"user_id={target_user_id}",
    )
