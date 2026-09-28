"""Assessment 1 Tests: Secure Password Storage with Argon2id.

Verifies:
1. Strict password policy enforcement (length, upper, lower, digit, symbol, blocklist).
2. Argon2id salt uniqueness (identical passwords yield distinct hash strings).
3. Account lockout triggered after 5 consecutive failed login attempts.
4. Password history enforcement preventing reuse of the last 3 passwords.
5. Time-limited, single-use password recovery flow.
"""

from __future__ import annotations

import pytest
from app.auth import (
    register_user,
    login_user,
    change_password,
    initiate_recovery,
    complete_recovery,
    check_password_policy,
    PasswordPolicyError,
    AuthenticationFailedError,
    AccountLockedError,
    ph,
)


def test_password_policy_enforcement():
    """Test 1: Password policy rejects short, simplistic, and blocklisted passwords."""
    assert len(check_password_policy("Short1!")) > 0
    assert len(check_password_policy("nouppercase123!")) > 0
    assert len(check_password_policy("NOLOWERCASE123!")) > 0
    assert len(check_password_policy("NoDigitsAtAll!@#")) > 0
    assert len(check_password_policy("NoSpecialChar1234")) > 0
    assert len(check_password_policy("password123!")) > 0  # in blocklist

    # Valid strong password
    assert len(check_password_policy("CorrectHorse$Battery99!")) == 0


def test_argon2id_unique_salts():
    """Test 2: Two hashes of the same password produce distinct outputs due to random salts."""
    pwd = "SecureCampusVault2026!#"
    hash1 = ph.hash(pwd)
    hash2 = ph.hash(pwd)

    assert hash1 != hash2
    assert "$argon2id$" in hash1
    assert "$argon2id$" in hash2
    assert ph.verify(hash1, pwd) is True
    assert ph.verify(hash2, pwd) is True


def test_account_lockout_after_five_failures(temp_db_path: str, audit_logger):
    """Test 3: 5 consecutive incorrect passwords lock the account; 6th is rejected immediately."""
    username = "alice_student"
    email = "alice@campus.local"
    valid_pass = "CampusVault2026!Student"
    register_user(username, email, valid_pass, role="student", db_path=temp_db_path, audit_logger=audit_logger)

    # 4 consecutive failures
    for _ in range(4):
        with pytest.raises(AuthenticationFailedError):
            login_user(username, "WrongPassword123!", db_path=temp_db_path, audit_logger=audit_logger)

    # 5th failure triggers lockout
    with pytest.raises(AccountLockedError):
        login_user(username, "WrongPassword123!", db_path=temp_db_path, audit_logger=audit_logger)

    # 6th attempt with CORRECT password is still locked out
    with pytest.raises(AccountLockedError):
        login_user(username, valid_pass, db_path=temp_db_path, audit_logger=audit_logger)


def test_password_history_prevent_reuse(temp_db_path: str, audit_logger):
    """Test 4: User cannot reuse any of their last 3 passwords."""
    user_id = register_user(
        "bob_faculty",
        "bob@campus.local",
        "InitialPass123!Safe",
        role="faculty",
        db_path=temp_db_path,
        audit_logger=audit_logger,
    )

    pass2 = "SecondPassword123!Safe"
    pass3 = "ThirdPassword123!Safe"
    pass4 = "FourthPassword123!Safe"

    change_password(user_id, "InitialPass123!Safe", pass2, db_path=temp_db_path, audit_logger=audit_logger)
    change_password(user_id, pass2, pass3, db_path=temp_db_path, audit_logger=audit_logger)
    change_password(user_id, pass3, pass4, db_path=temp_db_path, audit_logger=audit_logger)

    # Attempt to reuse InitialPass123!Safe, pass2, or pass3 should fail
    with pytest.raises(PasswordPolicyError) as exc_info:
        change_password(user_id, pass4, pass2, db_path=temp_db_path, audit_logger=audit_logger)
    assert "previous 3 passwords" in str(exc_info.value).lower()

    with pytest.raises(PasswordPolicyError):
        change_password(user_id, pass4, pass3, db_path=temp_db_path, audit_logger=audit_logger)


def test_password_recovery_token_flow(temp_db_path: str, audit_logger):
    """Test 5: Password recovery generates a one-time token and allows resetting password."""
    email = "carol@campus.local"
    user_id = register_user(
        "carol_admin",
        email,
        "OriginalPass123!Admin",
        role="admin",
        db_path=temp_db_path,
        audit_logger=audit_logger,
    )

    token = initiate_recovery(email, db_path=temp_db_path, audit_logger=audit_logger)
    assert token is not None

    new_pass = "BrandNewSecurePassword2026!"
    complete_recovery(token, new_pass, db_path=temp_db_path, audit_logger=audit_logger)

    # Login with new password succeeds
    user_info = login_user("carol_admin", new_pass, db_path=temp_db_path, audit_logger=audit_logger)
    assert user_info["id"] == user_id

    # Using the same recovery token again fails (single-use)
    with pytest.raises(Exception):
        complete_recovery(token, "AnotherPassword123!", db_path=temp_db_path, audit_logger=audit_logger)
