"""Assessment 9 Tests: STRIDE Threat Model Verification & Security Controls.

Verifies the 5 core STRIDE security controls implemented in CampusVault:
1. Spoofing (S): Blocked via Argon2id verification and 5-attempt account lockout.
2. Tampering (T): Blocked via HMAC-SHA256 canonical request signature checks.
3. Repudiation (R): Blocked via Ed25519 digital signatures and hash-chained audit logging.
4. Elevation of Privilege (E): Blocked via server-side RBAC denying student access to /admin.
5. Denial of Service (D): Mitigated via client IP sliding window rate limiting (429).
"""

from __future__ import annotations

import datetime
import json
import uuid
import pytest
from fastapi.testclient import TestClient

from api.hmac_auth import compute_hmac_signature
from api.main import create_api_app
from api.rate_limiter import SlidingWindowRateLimiter
from app.auth import (
    register_user,
    login_user,
    AccountLockedError,
    AuthenticationFailedError,
)
from app.main import create_portal_app
from app.session import create_session
from app.signatures import sign_document, verify_document_signature
from audit.logger import AuditLogger
from audit.verifier import verify_audit
from keyservice.models import KeyPurpose, KeyAlgorithm
from keyservice.service import KeyService


def test_stride_spoofing_prevented(temp_db_path: str, audit_logger: AuditLogger):
    """STRIDE Control T1 (Spoofing): Identity impersonation blocked by Argon2id & lockout."""
    target_user = "bob_faculty_stride"
    email = "bob_stride@campus.local"
    valid_pass = "SecurePass123!Safe"
    register_user(target_user, email, valid_pass, role="faculty", db_path=temp_db_path, audit_logger=audit_logger)

    # Attacker tries to guess password 5 times
    for _ in range(4):
        with pytest.raises(AuthenticationFailedError):
            login_user(target_user, "GuessedPassword123!", db_path=temp_db_path, audit_logger=audit_logger)

    # 5th attempt triggers lockout
    with pytest.raises(AccountLockedError):
        login_user(target_user, "GuessedPassword123!", db_path=temp_db_path, audit_logger=audit_logger)

    # Even if attacker gets the password right on attempt 6, account remains locked
    with pytest.raises(AccountLockedError):
        login_user(target_user, valid_pass, db_path=temp_db_path, audit_logger=audit_logger)


def test_stride_tampering_prevented(temp_db_path: str):
    """STRIDE Control T2 (Tampering): In-flight tampering of sensor data blocked by HMAC."""
    secret = b"StrideSharedSecretKey1234567890"
    limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=60)
    app = create_api_app(db_path=temp_db_path, shared_secret=secret, rate_limiter=limiter)
    client = TestClient(app)

    path = "/api/v1/telemetry"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    nonce = str(uuid.uuid4())
    original_payload = {"sensor_id": "sensor-01", "temperature": 21.0, "humidity": 45.0, "timestamp": timestamp}
    body = json.dumps(original_payload).encode("utf-8")
    sig = compute_hmac_signature("POST", path, timestamp, nonce, body, secret)

    # Attacker modifies temperature from 21.0 to 95.0 in transit
    tampered_body = json.dumps({"sensor_id": "sensor-01", "temperature": 95.0, "humidity": 45.0, "timestamp": timestamp}).encode("utf-8")
    headers = {
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": sig,
        "Content-Type": "application/json",
    }

    res = client.post(path, content=tampered_body, headers=headers)
    assert res.status_code == 401
    assert "signature" in res.json()["detail"].lower()


def test_stride_repudiation_prevented(key_service: KeyService):
    """STRIDE Control T3 (Repudiation): Cryptographic signatures bind author to content."""
    key_id = key_service.generate_key(
        purpose=KeyPurpose.SIGNING,
        algorithm=KeyAlgorithm.ED25519,
        created_by="faculty_bob",
    )
    doc = b"Grade Report CS301 -- Alice A, Bob B."
    bundle = sign_document(doc, signing_key_id=key_id, key_service=key_service, signer_id="faculty_bob")

    # Author cannot repudiate: signature verifies cryptographically
    assert verify_document_signature(doc, bundle, key_service=key_service) is True

    # Audit log contains non-repudiable event
    recent_logs = key_service.audit.get_recent(limit=5)
    assert any(log["action"] == "DOCUMENT_SIGNED" and log["identity"] == "faculty_bob" for log in recent_logs)


def test_stride_elevation_of_privilege_blocked(temp_db_path: str, master_key: bytes, audit_logger: AuditLogger):
    """STRIDE Control T6 (Privilege Escalation): Student role blocked from /admin routes."""
    student_id = register_user(
        "student_attacker",
        "student_attacker@campus.local",
        "StudentPass123!Safe",
        role="student",
        db_path=temp_db_path,
        audit_logger=audit_logger,
    )
    session_id = create_session(student_id, db_path=temp_db_path)

    portal = create_portal_app(db_path=temp_db_path, master_key=master_key)
    client = TestClient(portal)

    # Attempt to access admin dashboard with student session cookie
    client.cookies.set("cv_session", session_id)
    response = client.get("/admin/dashboard", follow_redirects=False)

    # Must be forbidden (403)
    assert response.status_code == 403


def test_stride_denial_of_service_mitigated(temp_db_path: str):
    """STRIDE Control T5 (Denial of Service): Burst requests trigger rate limiter."""
    secret = b"DosMitigationSecretKey1234567890"
    limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)
    app = create_api_app(db_path=temp_db_path, shared_secret=secret, rate_limiter=limiter)
    client = TestClient(app)

    path = "/api/v1/telemetry"
    # Send 3 permitted requests
    for i in range(3):
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        nonce = str(uuid.uuid4())
        body = json.dumps({"sensor_id": "s1", "temperature": 20.0, "humidity": 40.0, "timestamp": ts}).encode("utf-8")
        sig = compute_hmac_signature("POST", path, ts, nonce, body, secret)
        res = client.post(path, content=body, headers={"X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig, "Content-Type": "application/json"})
        assert res.status_code == 201

    # 4th request triggers rate limit defense
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    nonce = str(uuid.uuid4())
    body = json.dumps({"sensor_id": "s1", "temperature": 20.0, "humidity": 40.0, "timestamp": ts}).encode("utf-8")
    sig = compute_hmac_signature("POST", path, ts, nonce, body, secret)
    res = client.post(path, content=body, headers={"X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig, "Content-Type": "application/json"})

    assert res.status_code == 429
    assert "Retry-After" in res.headers


def test_stride_tampering_detected_in_audit_chain(temp_db_path: str, audit_logger: AuditLogger):
    """STRIDE Control T7 (Tampering): Audit log hash chain detects unauthorized edits."""
    audit_logger.log("AUTH", "user1", "LOGIN", "SUCCESS", "Normal event 1")
    audit_logger.log("DATA", "user2", "GRADE_CHANGE", "SUCCESS", "Normal event 2")

    # Attacker directly edits SQL database to hide trace
    import sqlite3
    conn = sqlite3.connect(temp_db_path)
    conn.execute("UPDATE audit_log SET action = 'LOGOUT' WHERE id = 2")
    conn.commit()
    conn.close()

    is_valid, errors = verify_audit(temp_db_path)
    assert is_valid is False
    assert len(errors) > 0
