"""Assessment 8 Tests: Cryptographic Key Management.

Verifies:
1. Key generation and encrypted storage at rest.
2. Key rotation (retiring old key and creating new active key).
3. Key revocation (blocking access to compromised keys).
4. Key destruction (cryptographic sanitization of key material).
5. Encrypted backup and restore round-trip.
"""

from __future__ import annotations

import sqlite3
import pytest
from keyservice.service import KeyService
from keyservice.models import (
    KeyPurpose,
    KeyAlgorithm,
    KeyState,
    KeyRevokedError,
    KeyDestroyedError,
)


def test_key_generation_and_storage_encrypted(key_service: KeyService, temp_db_path: str):
    """Test 1: Generated key is encrypted at rest; raw bytes do not appear in the DB."""
    key_id = key_service.generate_key(
        purpose=KeyPurpose.ENCRYPTION,
        algorithm=KeyAlgorithm.AES_256_GCM,
        created_by="admin_carol",
    )
    raw_key = key_service.get_key(key_id, caller="admin_carol")
    assert len(raw_key) == 32

    # Verify database contents: encrypted blob should not equal raw key bytes
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.execute("SELECT encrypted_key_material, key_nonce FROM crypto_keys WHERE id = ?", (key_id,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[0] != raw_key
    assert len(row[1]) == 12  # 96-bit AES-GCM nonce


def test_key_rotation(key_service: KeyService):
    """Test 2: Key rotation retires old key and creates new active key."""
    old_key_id = key_service.generate_key(
        purpose=KeyPurpose.ENCRYPTION,
        algorithm=KeyAlgorithm.AES_256_GCM,
    )
    new_key_id = key_service.rotate_key(old_key_id, caller="admin_carol")

    assert new_key_id != old_key_id
    active_key = key_service.get_active_key(KeyPurpose.ENCRYPTION)
    assert active_key.id == new_key_id
    assert active_key.state == KeyState.ACTIVE.value

    # Retired key can still be accessed for decrypting historical data
    old_key_bytes = key_service.get_key(old_key_id)
    assert len(old_key_bytes) == 32


def test_key_revocation(key_service: KeyService):
    """Test 3: Revoking a key immediately prevents its unwrapping."""
    key_id = key_service.generate_key(
        purpose=KeyPurpose.ENCRYPTION,
        algorithm=KeyAlgorithm.AES_256_GCM,
    )
    key_service.revoke_key(key_id, caller="admin_carol")

    with pytest.raises(KeyRevokedError) as exc_info:
        key_service.get_key(key_id, caller="app")
    assert "revoked" in str(exc_info.value).lower()


def test_key_destruction(key_service: KeyService, temp_db_path: str):
    """Test 4: Destroying a key zeroes out the stored material and raises KeyDestroyedError."""
    key_id = key_service.generate_key(
        purpose=KeyPurpose.SIGNING,
        algorithm=KeyAlgorithm.ED25519,
    )
    key_service.destroy_key(key_id, caller="admin_carol")

    with pytest.raises(KeyDestroyedError):
        key_service.get_key(key_id)

    # Check DB row is sanitized
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.execute("SELECT encrypted_key_material, state FROM crypto_keys WHERE id = ?", (key_id,))
    row = cursor.fetchone()
    conn.close()

    assert row[0] == b"\x00" * 32
    assert row[1] == KeyState.DESTROYED.value


def test_key_backup_restore(key_service: KeyService, tmp_path):
    """Test 5: Encrypted backup can be exported and restored to recover key access."""
    key_id = key_service.generate_key(
        purpose=KeyPurpose.HMAC,
        algorithm=KeyAlgorithm.HMAC_SHA256,
    )
    original_key_bytes = key_service.get_key(key_id)

    backup_file = tmp_path / "keys_backup.json"
    key_service.backup(backup_file, caller="admin_carol")
    assert backup_file.exists()

    # Create new empty key service with another DB and restore
    new_db = tmp_path / "restored.db"
    from app.database import init_db
    init_db(new_db)

    restored_service = KeyService(master_key=key_service.master_key, db_path=str(new_db))
    restored_service.restore(backup_file, caller="admin_carol")

    restored_key_bytes = restored_service.get_key(key_id)
    assert restored_key_bytes == original_key_bytes
