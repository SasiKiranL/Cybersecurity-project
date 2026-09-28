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

    conn = get_db_connection(db_path)
    try:
        locked_users = conn.execute(
            "SELECT COUNT(*) FROM users WHERE locked_until IS NOT NULL AND datetime(locked_until) > datetime('now')"
        ).fetchone()[0]
        failed_logins = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action LIKE '%LOGIN%' AND result = 'FAILURE'"
        ).fetchone()[0]
        total_audit_records = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()

    is_chain_valid, _ = verify_audit(db_path)
    posture = {
        "is_chain_valid": is_chain_valid,
        "locked_users": locked_users,
        "failed_logins": failed_logins,
        "active_keys": len([k for k in keys_list if k.state == "active"]),
        "total_audit_records": total_audit_records,
    }

    return templates.TemplateResponse(
        request=request,
        name="admin_dashboard.html",
        context={
            "user": user,
            "logs": recent_logs,
            "keys": keys_list,
            "audit_status": None,
            "posture": posture,
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

    conn = get_db_connection(db_path)
    try:
        locked_users = conn.execute(
            "SELECT COUNT(*) FROM users WHERE locked_until IS NOT NULL AND datetime(locked_until) > datetime('now')"
        ).fetchone()[0]
        failed_logins = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action LIKE '%LOGIN%' AND result = 'FAILURE'"
        ).fetchone()[0]
        total_audit_records = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()

    posture = {
        "is_chain_valid": is_valid,
        "locked_users": locked_users,
        "failed_logins": failed_logins,
        "active_keys": len([k for k in keys_list if k.state == "active"]),
        "total_audit_records": total_audit_records,
    }

    return templates.TemplateResponse(
        request=request,
        name="admin_dashboard.html",
        context={
            "user": user,
            "logs": recent_logs,
            "keys": keys_list,
            "audit_status": status_msg,
            "posture": posture,
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


@router.post("/fim/scan", response_class=HTMLResponse)
async def run_fim_scan(
    request: Request,
    user: dict = Depends(require_role("admin")),
):
    templates = request.app.state.templates
    db_path = request.app.state.db_path
    base_dir = request.app.state.base_dir
    key_service = request.app.state.key_service

    from audit.fim import verify_fim
    is_intact, findings = verify_fim(base_dir, db_path=db_path)
    if is_intact:
        fim_status = "SUCCESS: All core modules and security certificates match cryptographic SHA-256 baseline."
    else:
        fim_status = f"TAMPERING DETECTED: {len(findings)} integrity violation(s) found! {findings[0]}"

    audit = AuditLogger(db_path=db_path)
    recent_logs = audit.get_recent(limit=50)
    keys_list = key_service.list_keys()

    conn = get_db_connection(db_path)
    try:
        locked_users = conn.execute(
            "SELECT COUNT(*) FROM users WHERE locked_until IS NOT NULL AND datetime(locked_until) > datetime('now')"
        ).fetchone()[0]
        failed_logins = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action LIKE '%LOGIN%' AND result = 'FAILURE'"
        ).fetchone()[0]
        total_audit_records = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()

    is_chain_valid, _ = verify_audit(db_path)
    posture = {
        "is_chain_valid": is_chain_valid,
        "locked_users": locked_users,
        "failed_logins": failed_logins,
        "active_keys": len([k for k in keys_list if k.state == "active"]),
        "total_audit_records": total_audit_records,
    }

    return templates.TemplateResponse(
        request=request,
        name="admin_dashboard.html",
        context={
            "user": user,
            "logs": recent_logs,
            "keys": keys_list,
            "audit_status": None,
            "fim_status": fim_status,
            "posture": posture,
        },
    )


@router.get("/audit/export")
async def export_signed_audit_bundle(
    request: Request,
    user: dict = Depends(require_role("admin")),
):
    import datetime
    import json
    from fastapi.responses import Response
    from keyservice.models import KeyPurpose
    from app.signatures import sign_document

    db_path = request.app.state.db_path
    key_service = request.app.state.key_service

    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM audit_log ORDER BY id ASC")
        rows = [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

    is_valid, _ = verify_audit(db_path)
    payload = {
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "exported_by": user["username"],
        "record_count": len(rows),
        "chain_integrity_verified": is_valid,
        "records": rows,
    }
    raw_bytes = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")

    sign_key = key_service.get_active_key(KeyPurpose.SIGNING)
    sig_bundle = sign_document(
        plaintext=raw_bytes,
        signing_key_id=sign_key.id,
        key_service=key_service,
        signer_id=user["username"],
    )

    final_bundle = {
        "metadata": {
            "title": "CampusVault Forensic Audit Log Export",
            "compliance": "HCLTech Cybersecurity Practical Assessment",
            "signed_by": user["username"],
            "signing_key_id": sign_key.id,
            "signature_algorithm": "Ed25519",
        },
        "signature": sig_bundle,
        "audit_data": payload,
    }
    content = json.dumps(final_bundle, indent=2).encode("utf-8")

    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="campusvault_audit_export.signed.json"',
            "X-Audit-Verified": str(is_valid),
        },
    )
