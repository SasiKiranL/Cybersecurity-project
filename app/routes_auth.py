"""Authentication routes for CampusVault Portal."""

from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app.auth import (
    AccountLockedError,
    AuthenticationFailedError,
    PasswordPolicyError,
    change_password,
    complete_recovery,
    initiate_recovery,
    login_user,
    register_user,
)
from app.session import (
    create_session,
    terminate_all_user_sessions,
    terminate_session,
    validate_session,
)

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    templates = request.app.state.templates
    session_id = request.cookies.get("cv_session")
    user = validate_session(session_id, db_path=request.app.state.db_path)
    if user:
        role = user.get("role")
        if role == "student":
            return RedirectResponse(url="/student/dashboard", status_code=303)
        elif role == "faculty":
            return RedirectResponse(url="/faculty/dashboard", status_code=303)
        elif role == "admin":
            return RedirectResponse(url="/admin/dashboard", status_code=303)

    return templates.TemplateResponse(request=request, name="login.html", context={"user": None})


@router.post("/login", response_class=HTMLResponse)
async def login_action(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    templates = request.app.state.templates
    db_path = request.app.state.db_path

    # Defense-in-Depth: Rate limit login attempts per IP
    limiter = getattr(request.app.state, "login_limiter", None)
    if limiter is None:
        from api.rate_limiter import SlidingWindowRateLimiter
        limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=60)
        request.app.state.login_limiter = limiter

    client_ip = request.client.host if request.client else "127.0.0.1"
    allowed, retry_after = limiter.is_allowed(client_ip)
    if not allowed:
        from audit.logger import AuditLogger
        from audit.models import EventType, AuditResult
        audit = AuditLogger(db_path=db_path)
        audit.log(
            event_type=EventType.SYSTEM.value,
            identity=client_ip,
            action="LOGIN_RATE_LIMIT_EXCEEDED",
            result=AuditResult.DENIED.value,
            detail=f"Login rate limit reached for {client_ip}. Retry-After: {retry_after}s",
        )
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": f"Too many login attempts from this network. Please wait {retry_after} seconds before trying again.",
                "user": None,
            },
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    try:
        user_info = login_user(username, password, db_path=db_path)
        session_id = create_session(user_info["id"], db_path=db_path)

        role = user_info.get("role")
        target_url = "/student/dashboard"
        if role == "faculty":
            target_url = "/faculty/dashboard"
        elif role == "admin":
            target_url = "/admin/dashboard"

        redirect = RedirectResponse(url=target_url, status_code=303)
        # Set secure, HttpOnly, SameSite=Strict cookie
        redirect.set_cookie(
            key="cv_session",
            value=session_id,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=1800,  # 30 minutes
        )
        return redirect
    except AccountLockedError as e:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": str(e), "user": None},
            status_code=403,
        )
    except AuthenticationFailedError as e:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": str(e), "user": None},
            status_code=401,
        )
    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Authentication error.", "user": None},
            status_code=500,
        )


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    templates = request.app.state.templates
    return templates.TemplateResponse(request=request, name="register.html", context={"user": None})


@router.post("/register", response_class=HTMLResponse)
async def register_action(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form("student"),
):
    templates = request.app.state.templates
    db_path = request.app.state.db_path

    try:
        register_user(username, email, password, role=role, db_path=db_path)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "message": "Account registered successfully! You may now sign in.",
                "user": None,
            },
        )
    except PasswordPolicyError as e:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": str(e), "user": None},
            status_code=400,
        )
    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": str(e), "user": None},
            status_code=400,
        )


@router.get("/recover", response_class=HTMLResponse)
async def recover_page(request: Request):
    templates = request.app.state.templates
    return templates.TemplateResponse(request=request, name="recover.html", context={"user": None})


@router.post("/recover", response_class=HTMLResponse)
async def recover_action(
    request: Request,
    step: str = Form(...),
    email: str = Form(None),
    token: str = Form(None),
    new_password: str = Form(None),
):
    templates = request.app.state.templates
    db_path = request.app.state.db_path

    if step == "request":
        if not email:
            return templates.TemplateResponse(
                request=request,
                name="recover.html",
                context={"error": "Email is required.", "user": None},
                status_code=400,
            )
        rec_token = initiate_recovery(email, db_path=db_path)
        return templates.TemplateResponse(
            request=request,
            name="recover.html",
            context={"recovery_token": rec_token, "user": None},
        )
    elif step == "redeem":
        if not token or not new_password:
            return templates.TemplateResponse(
                request=request,
                name="recover.html",
                context={"error": "Token and new password required.", "user": None},
                status_code=400,
            )
        try:
            complete_recovery(token, new_password, db_path=db_path)
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={
                    "message": "Password reset successful! Please sign in with your new password.",
                    "user": None,
                },
            )
        except Exception as e:
            return templates.TemplateResponse(
                request=request,
                name="recover.html",
                context={"error": str(e), "user": None},
                status_code=400,
            )

    return RedirectResponse(url="/recover", status_code=303)


@router.get("/logout")
async def logout_action(request: Request):
    session_id = request.cookies.get("cv_session")
    if session_id:
        terminate_session(session_id, db_path=request.app.state.db_path)
    redirect = RedirectResponse(url="/login", status_code=303)
    redirect.delete_cookie(key="cv_session")
    return redirect


@router.post("/logout-all")
async def logout_all_action(request: Request):
    db_path = request.app.state.db_path
    session_id = request.cookies.get("cv_session")
    user = validate_session(session_id, db_path=db_path)
    if user:
        from audit.logger import AuditLogger
        from audit.models import EventType, AuditResult
        terminate_all_user_sessions(user["user_id"], db_path=db_path)
        audit = AuditLogger(db_path=db_path)
        audit.log(
            event_type=EventType.AUTH.value,
            identity=user["username"],
            action="LOGOUT_ALL_SESSIONS",
            result=AuditResult.SUCCESS.value,
            detail=f"Revoked all active sessions for user '{user['username']}'",
        )
    redirect = RedirectResponse(url="/login", status_code=303)
    redirect.delete_cookie(key="cv_session")
    return redirect
