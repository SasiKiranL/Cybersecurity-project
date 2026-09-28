"""Faculty portal routes for grade entry and authenticated document distribution."""

from __future__ import annotations

import datetime
import uuid
from pathlib import Path
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app.database import db_session, get_db_connection
from app.encryption import encrypt_file_data
from app.rbac import require_role
from app.signatures import save_detached_signature, sign_document
from audit.logger import AuditLogger
from audit.models import EventType, AuditResult
from keyservice.models import KeyPurpose

router = APIRouter(prefix="/faculty")


@router.get("/dashboard", response_class=HTMLResponse)
async def faculty_dashboard(
    request: Request,
    user: dict = Depends(require_role("faculty", "admin")),
):
    templates = request.app.state.templates
    db_path = request.app.state.db_path

    conn = get_db_connection(db_path)
    try:
        # Get list of students
        cursor = conn.execute("SELECT id, username, email FROM users WHERE role = 'student'")
        students = [dict(row) for row in cursor.fetchall()]

        # Get marks entered by this faculty
        cursor = conn.execute(
            """
            SELECT m.id, m.course_code, m.course_name, m.score, m.semester, m.entered_at,
                   u.username AS student_username
            FROM marks m
            JOIN users u ON m.student_id = u.id
            WHERE m.faculty_id = ?
            ORDER BY m.entered_at DESC
            """,
            (user["user_id"],),
        )
        marks = [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

    return templates.TemplateResponse(
        request=request,
        name="faculty_dashboard.html",
        context={"user": user, "students": students, "marks": marks},
    )


@router.post("/marks")
async def enter_grade(
    request: Request,
    student_id: str = Form(...),
    course_code: str = Form(...),
    course_name: str = Form(...),
    score: int = Form(...),
    semester: str = Form("Fall 2026"),
    user: dict = Depends(require_role("faculty", "admin")),
):
    if score < 0 or score > 100:
        raise HTTPException(status_code=400, detail="Score must be between 0 and 100.")

    db_path = request.app.state.db_path
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    with db_session(db_path) as conn:
        conn.execute(
            """
            INSERT INTO marks (student_id, faculty_id, course_code, course_name, score, semester, entered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (student_id, user["user_id"], course_code.strip(), course_name.strip(), score, semester.strip(), now),
        )

    audit = AuditLogger(db_path=db_path)
    audit.log(
        event_type=EventType.DATA.value,
        identity=user["username"],
        action="MARK_ENTERED",
        result=AuditResult.SUCCESS.value,
        detail=f"student_id={student_id} course={course_code} score={score}",
    )

    return RedirectResponse(url="/faculty/dashboard", status_code=303)


@router.post("/documents")
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    user: dict = Depends(require_role("faculty", "admin")),
):
    key_service = request.app.state.key_service
    db_path = request.app.state.db_path
    settings = request.app.state.settings

    # Read plaintext
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    doc_id = str(uuid.uuid4())
    safe_filename = Path(file.filename or "uploaded_file.txt").name

    # 1. Sign plaintext with Ed25519
    sign_key_id = key_service.get_active_key(KeyPurpose.SIGNING).id
    sig_bundle = sign_document(
        plaintext=content,
        signing_key_id=sign_key_id,
        key_service=key_service,
        signer_id=user["username"],
    )

    # 2. Envelope encrypt plaintext with AES-256-GCM
    enc_bundle = encrypt_file_data(
        plaintext=content,
        key_service=key_service,
        uploader_id=user["username"],
    )

    # 3. Store encrypted bytes and detached signature file
    files_dir = settings.files_dir
    files_dir.mkdir(parents=True, exist_ok=True)

    sig_rel = f"files/{doc_id}.sig"
    enc_rel = f"files/{doc_id}.enc"

    save_detached_signature(sig_bundle, files_dir / f"{doc_id}.sig")
    (files_dir / f"{doc_id}.enc").write_bytes(enc_bundle.serialize())

    # 4. Insert into documents table
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with db_session(db_path) as conn:
        conn.execute(
            """
            INSERT INTO documents
            (id, filename, uploader_id, encryption_key_id, file_path, signature_path, signing_key_id, content_hash, uploaded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                doc_id,
                safe_filename,
                user["user_id"],
                enc_bundle.kek_id,
                enc_rel,
                sig_rel,
                sign_key_id,
                sig_bundle["content_hash"],
                now,
            ),
        )

    return RedirectResponse(url="/faculty/dashboard", status_code=303)
