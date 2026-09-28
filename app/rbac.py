"""Role-Based Access Control (RBAC) and ownership verification for CampusVault.

Enforces:
- Deny-by-default architecture
- Role-to-permission mapping
- Ownership checks for student records
- Audit logging of access denial events
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Optional, Union

from fastapi import Depends, HTTPException, Request, status

from app.database import get_db_connection
from app.session import validate_session
from audit.logger import AuditLogger
from audit.models import EventType, AuditResult


def get_role_permissions(role: str, db_path: Union[str, Path, None] = None) -> list[str]:
    """Retrieve granted permissions for a given role from the database."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT permissions FROM roles WHERE name = ?", (role,))
        row = cursor.fetchone()
        if not row:
            return []
        return json.loads(row["permissions"])
    finally:
        conn.close()


def has_permission(role: str, permission: str, db_path: Union[str, Path, None] = None) -> bool:
    """Check if the role is granted the specific permission."""
    perms = get_role_permissions(role, db_path)
    return permission in perms


def check_ownership(user_id: str, resource_owner_id: str) -> bool:
    """Verify that user_id matches the resource owner ID."""
    if not user_id or not resource_owner_id:
        return False
    return str(user_id) == str(resource_owner_id)


def get_current_user(request: Request) -> dict:
    """Extract and validate the authenticated session from cookies or headers."""
    db_path = getattr(request.app.state, "db_path", None)
    session_id = request.cookies.get("cv_session")

    # Also support Authorization header Bearer token for programmatic API access
    if not session_id:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            session_id = auth_header.split(" ", 1)[1].strip()

    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    user = validate_session(session_id, db_path=db_path)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or is invalid. Please log in again.",
        )

    return user


def require_role(*roles: str) -> Callable:
    """FastAPI dependency to require the user have one of the specified roles."""
    def role_checker(request: Request, user: dict = Depends(get_current_user)) -> dict:
        user_role = user.get("role")
        if user_role not in roles:
            db_path = getattr(request.app.state, "db_path", None)
            audit = AuditLogger(db_path=db_path)
            audit.log(
                event_type=EventType.ACCESS.value,
                identity=user.get("username", "unknown"),
                action="ROLE_ACCESS_DENIED",
                result=AuditResult.DENIED.value,
                detail=f"Required one of {roles}, got '{user_role}' on path '{request.url.path}'",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: your role is not authorized to access this resource.",
            )
        return user

    return role_checker


def require_permission(permission: str) -> Callable:
    """FastAPI dependency to require the user possess a specific permission."""
    def permission_checker(request: Request, user: dict = Depends(get_current_user)) -> dict:
        user_role = user.get("role")
        db_path = getattr(request.app.state, "db_path", None)
        if not has_permission(user_role, permission, db_path=db_path):
            audit = AuditLogger(db_path=db_path)
            audit.log(
                event_type=EventType.ACCESS.value,
                identity=user.get("username", "unknown"),
                action="PERMISSION_DENIED",
                result=AuditResult.DENIED.value,
                detail=f"Missing permission '{permission}' for role '{user_role}' on path '{request.url.path}'",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: required permission is missing.",
            )
        return user

    return permission_checker
