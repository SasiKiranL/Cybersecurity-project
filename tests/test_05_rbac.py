"""Assessment 5 Tests: Role-Based Access Control (RBAC) and Least Privilege.

Verifies:
1. Student can read own marks.
2. Student is blocked from reading peer's marks (ownership enforcement).
3. Student is denied administrative privileges (keys, audit, user management).
4. Faculty has permissions to upload files and enter marks.
5. Inactive or expired sessions are rejected.
"""

from __future__ import annotations

import datetime
import pytest
from app.auth import register_user
from app.session import create_session, validate_session, terminate_session
from app.rbac import has_permission, check_ownership
from app.database import db_session


def test_rbac_student_can_read_own_marks(temp_db_path: str):
    """Test 1: Student role has permission to read own marks."""
    assert has_permission("student", "marks:read_own", db_path=temp_db_path) is True
    assert has_permission("student", "documents:download", db_path=temp_db_path) is True


def test_rbac_student_cannot_view_peer_marks():
    """Test 2: Ownership verification ensures student A cannot access student B's data."""
    student_a_id = "user-alice-12345"
    student_b_id = "user-charlie-67890"

    assert check_ownership(student_a_id, student_a_id) is True
    assert check_ownership(student_a_id, student_b_id) is False


def test_rbac_student_denied_admin_panel(temp_db_path: str):
    """Test 3: Student role does not have admin permissions."""
    assert has_permission("student", "audit:read", db_path=temp_db_path) is False
    assert has_permission("student", "keys:manage", db_path=temp_db_path) is False
    assert has_permission("student", "users:manage", db_path=temp_db_path) is False
    assert has_permission("student", "marks:write_assigned", db_path=temp_db_path) is False


def test_rbac_faculty_permissions(temp_db_path: str):
    """Test 4: Faculty role possesses marks:write_assigned and documents:upload."""
    assert has_permission("faculty", "marks:write_assigned", db_path=temp_db_path) is True
    assert has_permission("faculty", "documents:upload", db_path=temp_db_path) is True
    assert has_permission("faculty", "marks:read_assigned", db_path=temp_db_path) is True
    # Faculty does NOT possess admin keys/users management
    assert has_permission("faculty", "keys:manage", db_path=temp_db_path) is False
    assert has_permission("faculty", "users:manage", db_path=temp_db_path) is False


def test_session_expiry_and_invalidation(temp_db_path: str, audit_logger):
    """Test 5: Expired or logged-out sessions are rejected."""
    user_id = register_user(
        "alice_test",
        "alice_test@campus.local",
        "SecurePassword123!@",
        role="student",
        db_path=temp_db_path,
        audit_logger=audit_logger,
    )

    session_id = create_session(user_id, db_path=temp_db_path)
    user_data = validate_session(session_id, db_path=temp_db_path)
    assert user_data is not None
    assert user_data["user_id"] == user_id

    # Test explicit logout / termination
    terminate_session(session_id, db_path=temp_db_path)
    assert validate_session(session_id, db_path=temp_db_path) is None

    # Test expired session
    expired_session_id = create_session(user_id, db_path=temp_db_path)
    past_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=45)).isoformat()
    with db_session(temp_db_path) as conn:
        conn.execute("UPDATE sessions SET expires_at = ? WHERE id = ?", (past_time, expired_session_id))

    assert validate_session(expired_session_id, db_path=temp_db_path) is None
