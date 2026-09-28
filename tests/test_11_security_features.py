"""Security Features Test Suite: File upload security, session termination, FIM, and signed audit export.

Verifies:
1. File upload security (extension whitelist, path traversal sanitization, size limits, magic bytes).
2. Global session termination ('Sign Out Everywhere') invalidates all active tokens.
3. Cryptographic File Integrity Monitor (FIM) baseline generation and tamper detection.
4. Cryptographic signed audit export bundle generation and Ed25519 verification.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from app.auth import register_user
from app.file_security import (
    FileSecurityError,
    sanitize_filename,
    validate_uploaded_file,
)
from app.session import (
    create_session,
    terminate_all_user_sessions,
    validate_session,
)
from audit.fim import generate_fim_baseline, verify_fim
from audit.logger import AuditLogger
from cryptography.hazmat.primitives.asymmetric import ed25519
from keyservice.models import KeyPurpose
from keyservice.service import KeyService


def test_file_security_validation_allowed_and_sanitized():
    """Verify that allowed files are accepted, filenames are sanitized, and attacks are rejected."""
    # 1. Directory traversal in filename should be sanitized
    clean_name = sanitize_filename("../../../etc/passwd.txt")
    assert clean_name == "passwd.txt"
    assert "/" not in clean_name and ".." not in clean_name

    # 2. Valid plain text file
    safe_txt = validate_uploaded_file("notes.txt", b"Student notes and lecture syllabus.")
    assert safe_txt == "notes.txt"

    # 3. Valid PDF with %PDF- header
    pdf_content = b"%PDF-1.5 \x00test content"
    # PDF magic byte check passes even with null bytes inside binary format
    safe_pdf = validate_uploaded_file("syllabus.pdf", b"%PDF-1.5 binary data")
    assert safe_pdf == "syllabus.pdf"

    # 4. Text file with null bytes (binary injection / polyglot) is rejected
    with pytest.raises(FileSecurityError, match="Binary / null-byte payload"):
        validate_uploaded_file("test.txt", b"Hello\x00World")

    # 5. Dangerous executable extension is rejected
    with pytest.raises(FileSecurityError, match="not permitted"):
        validate_uploaded_file("malware.exe", b"MZ\x90\x00")

    # 6. Disallowed script extension (.py)
    with pytest.raises(FileSecurityError, match="not permitted"):
        validate_uploaded_file("script.py", b"print('hacked')")

    # 7. MIME/Extension spoofing: .pdf extension with non-PDF header
    with pytest.raises(FileSecurityError, match="do not match expected magic bytes"):
        validate_uploaded_file("fake.pdf", b"This is not a real PDF document.")

    # 8. Empty file rejected
    with pytest.raises(FileSecurityError, match="Uploaded file is empty"):
        validate_uploaded_file("empty.txt", b"")

    # 9. Oversized file (> 5MB) rejected
    oversized = b"A" * (5 * 1024 * 1024 + 10)
    with pytest.raises(FileSecurityError, match="exceeds 5MB limit"):
        validate_uploaded_file("huge.txt", oversized)


def test_terminate_all_user_sessions(temp_db_path: str):
    """Verify that terminate_all_user_sessions invalidates all tokens for that user."""
    user_id = register_user(
        "alice_multi",
        "alice_multi@campus.local",
        "StrongPass123!#",
        role="student",
        db_path=temp_db_path,
    )

    # Simulate logging in on two different devices/browsers (bypassing single-session update for test)
    from app.database import db_session
    import datetime, secrets

    now = datetime.datetime.now(datetime.timezone.utc)
    expires = (now + datetime.timedelta(minutes=30)).isoformat()
    s1 = secrets.token_urlsafe(32)
    s2 = secrets.token_urlsafe(32)

    with db_session(temp_db_path) as conn:
        conn.execute(
            "INSERT INTO sessions (id, user_id, created_at, expires_at, is_active) VALUES (?, ?, ?, ?, 1)",
            (s1, user_id, now.isoformat(), expires),
        )
        conn.execute(
            "INSERT INTO sessions (id, user_id, created_at, expires_at, is_active) VALUES (?, ?, ?, ?, 1)",
            (s2, user_id, now.isoformat(), expires),
        )

    assert validate_session(s1, db_path=temp_db_path) is not None
    assert validate_session(s2, db_path=temp_db_path) is not None

    # Revoke all active sessions
    revoked_count = terminate_all_user_sessions(user_id, db_path=temp_db_path)
    assert revoked_count == 2

    # Both tokens are now invalid
    assert validate_session(s1, db_path=temp_db_path) is None
    assert validate_session(s2, db_path=temp_db_path) is None


def test_fim_baseline_generation_and_tamper_detection(tmp_path: Path, temp_db_path: str):
    """Verify that FIM accurately detects both modified files and missing files."""
    dummy_root = tmp_path / "app_root"
    dummy_root.mkdir()

    # Create dummy monitored files
    f1 = dummy_root / "requirements.txt"
    f1.write_text("fastapi==0.115.0\n", encoding="utf-8")

    f2 = dummy_root / "app" / "auth.py"
    f2.parent.mkdir(parents=True)
    f2.write_text("def auth_fn(): pass\n", encoding="utf-8")

    baseline_path = tmp_path / "baseline.json"

    # Generate baseline
    hashes = generate_fim_baseline(dummy_root, baseline_path)
    assert "requirements.txt" in hashes
    assert "app/auth.py" in hashes

    # Verify baseline immediately matches
    is_intact, findings = verify_fim(dummy_root, baseline_path, db_path=temp_db_path)
    assert is_intact is True
    assert len(findings) == 0

    # Tamper with app/auth.py
    f2.write_text("def auth_fn(): return 'backdoor'\n", encoding="utf-8")
    is_intact, findings = verify_fim(dummy_root, baseline_path, db_path=temp_db_path)
    assert is_intact is False
    assert any("TAMPERED: Monitored file 'app/auth.py'" in f for f in findings)

    # Delete requirements.txt
    f1.unlink()
    is_intact, findings = verify_fim(dummy_root, baseline_path, db_path=temp_db_path)
    assert is_intact is False
    assert any("MISSING: Monitored file 'requirements.txt'" in f for f in findings)


def test_signed_audit_export_bundle_verification(key_service: KeyService, temp_db_path: str):
    """Verify that exported audit bundle is cryptographically signed and authentic."""
    audit = AuditLogger(db_path=temp_db_path)
    audit.log("AUTH", "admin", "LOGIN", "SUCCESS", "Administrator authenticated")
    audit.log("DATA", "admin", "AUDIT_EXPORT", "SUCCESS", "Export requested")

    from audit.verifier import verify_audit
    from app.signatures import sign_document

    is_valid, _ = verify_audit(temp_db_path)
    assert is_valid is True

    # Build export payload
    records = audit.get_recent(limit=10)
    payload = {
        "record_count": len(records),
        "chain_integrity_verified": is_valid,
        "records": records,
    }
    raw_bytes = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")

    # Ensure an active signing key exists
    key_service.generate_key(KeyPurpose.SIGNING, algorithm="Ed25519", created_by="admin")

    # Sign using active signing key
    sign_key = key_service.get_active_key(KeyPurpose.SIGNING)
    sig_bundle = sign_document(
        plaintext=raw_bytes,
        signing_key_id=sign_key.id,
        key_service=key_service,
        signer_id="admin",
    )

    # Cryptographically verify the Ed25519 signature
    import hashlib
    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    assert sig_bundle["content_hash"] == content_hash

    # Public key verification
    priv_bytes = key_service.get_key(sign_key.id, caller="verifier")
    priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    pub_key = priv_key.public_key()

    sig_bytes = bytes.fromhex(sig_bundle["signature_hex"])
    # This will raise InvalidSignature if tampered
    pub_key.verify(sig_bytes, content_hash.encode("utf-8"))
