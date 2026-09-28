"""Administrator security operations center routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app.database import get_db_connection
from app.rbac import require_role
from audit.logger import AuditLogger
from audit.verifier import verify_audit

router = APIRouter(prefix="/admin")


@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    user: dict = Depends(require_role("admin")),
):
    templates = request.app.state.templates
    db_path = request.app.state.db_path
    key_service = request.app.state.key_service

    audit = AuditLogger(db_path=db_path)
    recent_logs = audit.get_recent(limit=50)
    keys_list = key_service.list_keys()

    return templates.TemplateResponse(
        request=request,
        name="admin_dashboard.html",
        context={
            "user": user,
            "logs": recent_logs,
            "keys": keys_list,
            "audit_status": None,
        },
    )


@router.post("/audit/verify", response_class=HTMLResponse)
async def verify_audit_chain(
    request: Request,
    user: dict = Depends(require_role("admin")),
):
    templates = request.app.state.templates
    db_path = request.app.state.db_path
    key_service = request.app.state.key_service

    is_valid, errors = verify_audit(db_path)
    if is_valid:
        status_msg = "SUCCESS: All cryptographic hashes and chain links are verified. Zero tampering detected."
    else:
        status_msg = f"TAMPERING DETECTED: {len(errors)} anomalies found! First violation: {errors[0]}"

    audit = AuditLogger(db_path=db_path)
    recent_logs = audit.get_recent(limit=50)
    keys_list = key_service.list_keys()

    return templates.TemplateResponse(
        request=request,
        name="admin_dashboard.html",
        context={
            "user": user,
            "logs": recent_logs,
            "keys": keys_list,
            "audit_status": status_msg,
        },
    )


@router.post("/keys/rotate")
async def rotate_key_action(
    request: Request,
    key_id: str = Form(...),
    user: dict = Depends(require_role("admin")),
):
    key_service = request.app.state.key_service
    key_service.rotate_key(key_id, caller=user["username"])
    return RedirectResponse(url="/admin/dashboard", status_code=303)


@router.post("/keys/revoke")
async def revoke_key_action(
    request: Request,
    key_id: str = Form(...),
    user: dict = Depends(require_role("admin")),
):
    key_service = request.app.state.key_service
    key_service.revoke_key(key_id, caller=user["username"])
    return RedirectResponse(url="/admin/dashboard", status_code=303)
