"""CampusVault Main Web Portal Application.

Equipped with:
- Security HTTP Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- Error handlers returning safe generic user messages
- Role-based routing (Auth, Student, Faculty, Admin)
- Jinja2 template rendering
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional, Union

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings
from app.database import init_db
from app.routes_admin import router as admin_router
from app.routes_auth import router as auth_router
from app.routes_faculty import router as faculty_router
from app.routes_student import router as student_router
from app.session import validate_session
from audit.logger import AuditLogger
from audit.models import EventType, AuditResult
from keyservice.service import KeyService


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects defense-in-depth HTTP security response headers."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:;"
        )
        return response


def create_portal_app(
    db_path: Union[str, Path, None] = None,
    master_key: Optional[bytes] = None,
) -> FastAPI:
    """Application factory for CampusVault Web Portal."""
    settings = get_settings()
    app = FastAPI(title="CampusVault Academic Portal", version="1.0.0")

    # Initialize DB if not initialized
    target_db = Path(db_path) if db_path else settings.db_path
    init_db(target_db)

    # Initialize KeyService
    mk = master_key if master_key is not None else settings.get_master_key_bytes()
    key_service = KeyService(master_key=mk, db_path=target_db)

    templates_dir = BASE_DIR / "app" / "templates"
    templates = Jinja2Templates(directory=str(templates_dir))

    # App state
    app.state.base_dir = BASE_DIR
    app.state.settings = settings
    app.state.db_path = target_db
    app.state.key_service = key_service
    app.state.templates = templates

    # Register middleware
    app.add_middleware(SecurityHeadersMiddleware)

    # Register routers
    app.include_router(auth_router)
    app.include_router(student_router)
    app.include_router(faculty_router)
    app.include_router(admin_router)

    # Root redirect
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        session_id = request.cookies.get("cv_session")
        user = validate_session(session_id, db_path=app.state.db_path)
        if not user:
            return RedirectResponse(url="/login", status_code=303)
        role = user.get("role")
        if role == "student":
            return RedirectResponse(url="/student/dashboard", status_code=303)
        elif role == "faculty":
            return RedirectResponse(url="/faculty/dashboard", status_code=303)
        elif role == "admin":
            return RedirectResponse(url="/admin/dashboard", status_code=303)
        return RedirectResponse(url="/login", status_code=303)

    # Custom Exception Handlers for safe, generic user-facing responses
    @app.exception_handler(HTTPException)
    async def custom_http_exception_handler(request: Request, exc: HTTPException):
        # Audit log the denial or error
        audit = AuditLogger(db_path=app.state.db_path)
        client_ip = request.client.host if request.client else "unknown"
        audit.log(
            event_type=EventType.SYSTEM.value,
            identity=client_ip,
            action="HTTP_EXCEPTION",
            result=AuditResult.FAILURE.value,
            detail=f"Status {exc.status_code} on path {request.url.path}: {exc.detail}",
        )

        from fastapi.responses import JSONResponse

        if "text/html" in request.headers.get("accept", ""):
            return templates.TemplateResponse(
                request=request,
                name="error.html",
                context={
                    "title": f"Notice ({exc.status_code})",
                    "message": exc.detail,
                    "user": None,
                },
                status_code=exc.status_code,
            )
        return JSONResponse(content={"error": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        # Generic error message to user; detail only in audit log
        audit = AuditLogger(db_path=app.state.db_path)
        client_ip = request.client.host if request.client else "unknown"
        audit.log(
            event_type=EventType.SYSTEM.value,
            identity=client_ip,
            action="UNHANDLED_EXCEPTION",
            result=AuditResult.FAILURE.value,
            detail=f"Exception {type(exc).__name__} on path {request.url.path}",
        )
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={
                "title": "System Notice",
                "message": "An unexpected error occurred. The incident has been recorded in the secure audit log.",
                "user": None,
            },
            status_code=500,
        )

    return app


portal_app = create_portal_app()
