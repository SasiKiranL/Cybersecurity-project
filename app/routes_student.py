"""Student portal routes with ownership verification and authenticated downloads."""

from __future__ import annotations

from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse

from app.database import get_db_connection
from app.encryption import EncryptedBundle, decrypt_file_data
from app.rbac import get_current_user, require_role
from app.signatures import load_detached_signature, verify_document_signature

router = APIRouter(prefix="/student")


@router.get("/dashboard", response_class=HTMLResponse)
async def student_dashboard(
    request: Request,
    user: dict = Depends(require_role("student", "admin")),
):
    templates = request.app.state.templates
    db_path = request.app.state.db_path

    conn = get_db_connection(db_path)
    try:
        # Enforce Ownership: only retrieve marks for this authenticated student
        cursor = conn.execute(
            """
            SELECT id, course_code, course_name, score, semester, entered_at
            FROM marks
            WHERE student_id = ?
            ORDER BY entered_at DESC
            """,
            (user["user_id"],),
        )
        marks = [dict(row) for row in cursor.fetchall()]

        # Retrieve available documents
        cursor = conn.execute(
            """
            SELECT id, filename, content_hash, uploaded_at
            FROM documents
            ORDER BY uploaded_at DESC
            """
        )
        docs = [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

    return templates.TemplateResponse(
        request=request,
        name="student_dashboard.html",
        context={"user": user, "marks": marks, "documents": docs},
    )


@router.get("/document/{doc_id}/download")
async def download_document(
    doc_id: str,
    request: Request,
    user: dict = Depends(require_role("student", "faculty", "admin")),
):
    """Decrypt and verify digital signature of academic document before delivery."""
    db_path = request.app.state.db_path
    key_service = request.app.state.key_service
    base_dir = request.app.state.base_dir

    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            """
            SELECT id, filename, file_path, signature_path, encryption_key_id, signing_key_id
            FROM documents
            WHERE id = ?
            """,
            (doc_id,),
        )
        doc = cursor.fetchone()
    finally:
        conn.close()

    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found.",
        )

    # 1. Resolve file paths
    enc_file_path = base_dir / "data" / doc["file_path"]
    sig_file_path = base_dir / "data" / doc["signature_path"]

    if not enc_file_path.exists() or not sig_file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Encrypted archive or digital signature file missing on storage.",
        )

    # 2. Decrypt file using KeyService KEK and AES-256-GCM
    try:
        encrypted_data = enc_file_path.read_bytes()
        bundle = EncryptedBundle.deserialize(encrypted_data)
        plaintext = decrypt_file_data(
            bundle=bundle,
            key_service=key_service,
            caller_id=user["username"],
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Decryption failed: file integrity check failure.",
        )

    # 3. Verify digital signature using Ed25519
    try:
        sig_bundle = load_detached_signature(sig_file_path)
        is_valid = verify_document_signature(
            plaintext=plaintext,
            signature_bundle=sig_bundle,
            key_service=key_service,
            verifier_id=user["username"],
        )
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Security rejection: document signature is invalid or tampered.",
            )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security rejection: digital signature verification failed.",
        )

    # 4. Deliver authenticated plaintext
    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{doc["filename"]}"',
            "X-Signature-Verified": "True",
            "X-Content-Type-Options": "nosniff",
        },
    )
