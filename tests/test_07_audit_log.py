"""Assessment 7 Tests: Tamper-Evident Audit Logging.

Verifies:
1. Hash chain creation and validity.
2. Tampering detection (integrity violation).
3. Sensitive data scrubbing (passwords/tokens never logged in detail).
4. Genesis block initialization.
5. Error resiliency on database write failures.
"""

from __future__ import annotations

import sqlite3
import pytest
from audit.logger import AuditLogger
from audit.verifier import verify_audit
from audit.models import GENESIS_HASH


def test_audit_genesis_hash(audit_logger: AuditLogger, temp_db_path: str):
    """Test 1: First audit entry has prev_hash equal to 64 zeros."""
    audit_logger.log(
        event_type="SYSTEM",
        identity="system",
        action="SERVER_START",
        result="SUCCESS",
        detail="Server initialized",
    )
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.execute("SELECT prev_hash, record_hash FROM audit_log WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[0] == GENESIS_HASH
    assert len(row[1]) == 64


def test_audit_hash_chain_validity(audit_logger: AuditLogger, temp_db_path: str):
    """Test 2: A sequence of events forms an unbroken cryptographic chain."""
    for i in range(10):
        audit_logger.log(
            event_type="AUTH",
            identity=f"user_{i}",
            action="LOGIN_ATTEMPT",
            result="SUCCESS" if i % 2 == 0 else "FAILURE",
            detail=f"Attempt {i}",
        )

    is_valid, errors = verify_audit(temp_db_path)
    assert is_valid is True
    assert len(errors) == 0


def test_audit_tampering_detected(audit_logger: AuditLogger, temp_db_path: str):
    """Test 3: Modifying a record's detail or hash breaks verification."""
    for i in range(5):
        audit_logger.log(
            event_type="DATA",
            identity="faculty_01",
            action="GRADE_ENTRY",
            result="SUCCESS",
            detail=f"Course CS{100+i}",
        )

    # Tamper with record #3
    conn = sqlite3.connect(temp_db_path)
    conn.execute("UPDATE audit_log SET detail = 'Malicious alteration' WHERE id = 3")
    conn.commit()
    conn.close()

    is_valid, errors = verify_audit(temp_db_path)
    assert is_valid is False
    assert len(errors) > 0
    assert any("record 3" in e for e in errors)


def test_audit_detail_scrubbing(audit_logger: AuditLogger, temp_db_path: str):
    """Test 4: Secrets in details are scrubbed and replaced with [REDACTED]."""
    audit_logger.log(
        event_type="AUTH",
        identity="student_01",
        action="REGISTRATION",
        result="SUCCESS",
        detail="User registered with password='SuperSecretPassword123!' and token='abc123secrettoken'",
    )

    conn = sqlite3.connect(temp_db_path)
    cursor = conn.execute("SELECT detail FROM audit_log ORDER BY id DESC LIMIT 1")
    detail = cursor.fetchone()[0]
    conn.close()

    assert "SuperSecretPassword123!" not in detail
    assert "abc123secrettoken" not in detail
    assert "[REDACTED]" in detail


def test_audit_db_failure_resilience(tmp_path):
    """Test 5: Audit logger does not crash application if database is inaccessible."""
    invalid_db_path = str(tmp_path / "non_existent_dir" / "nested" / "invalid.db")
    faulty_logger = AuditLogger(db_path=invalid_db_path)

    # Should not raise an exception, returns None
    result = faulty_logger.log(
        event_type="SYSTEM",
        identity="system",
        action="EMERGENCY_SHUTDOWN",
        result="FAILURE",
        detail="Simulated failure",
    )
    assert result is None
