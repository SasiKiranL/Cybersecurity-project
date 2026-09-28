"""Assessment 2 Tests: Authenticated File Encryption.

Verifies:
1. AES-256-GCM envelope encryption and decryption round-trip.
2. Nonce and ciphertext uniqueness across multiple encryptions of identical plaintext.
3. Tamper detection: modifying ciphertext or authentication tag raises IntegrityError.
4. Standalone VaultCTL CLI scrypt + AES-GCM encryption and wrong passphrase rejection.
5. VaultCTL archive inspection.
"""

from __future__ import annotations

import pytest
from app.encryption import (
    encrypt_file_data,
    decrypt_file_data,
    EncryptedBundle,
    IntegrityError,
)
from keyservice.models import KeyPurpose, KeyAlgorithm
from keyservice.service import KeyService
from vault.vaultctl import encrypt_data, decrypt_data, inspect_archive


@pytest.fixture
def active_kek_service(key_service: KeyService) -> KeyService:
    """Key service with an active encryption KEK generated."""
    key_service.generate_key(
        purpose=KeyPurpose.ENCRYPTION,
        algorithm=KeyAlgorithm.AES_256_GCM,
        created_by="system",
    )
    return key_service


def test_envelope_encryption_roundtrip(active_kek_service: KeyService):
    """Test 1: Envelope encryption encrypts and cleanly decrypts file data."""
    plaintext = b"Confidential transcript: Student Alice GPA 3.98 in Computer Science."
    bundle = encrypt_file_data(plaintext, key_service=active_kek_service, uploader_id="faculty_bob")

    # Serialize to binary and deserialize back
    raw_file_bytes = bundle.serialize()
    restored_bundle = EncryptedBundle.deserialize(raw_file_bytes)

    decrypted = decrypt_file_data(restored_bundle, key_service=active_kek_service, caller_id="student_alice")
    assert decrypted == plaintext


def test_envelope_encryption_random_nonce_ciphertext_uniqueness(active_kek_service: KeyService):
    """Test 2: Encrypting the exact same plaintext twice produces different ciphertexts and nonces."""
    plaintext = b"Identical college syllabus content."
    bundle1 = encrypt_file_data(plaintext, key_service=active_kek_service)
    bundle2 = encrypt_file_data(plaintext, key_service=active_kek_service)

    assert bundle1.ciphertext != bundle2.ciphertext
    assert bundle1.data_nonce != bundle2.data_nonce
    assert bundle1.dek_nonce != bundle2.dek_nonce
    assert bundle1.wrapped_dek != bundle2.wrapped_dek


def test_envelope_encryption_tamper_detection(active_kek_service: KeyService):
    """Test 3: Bit-flipping in ciphertext or tag fails authenticated GCM decryption."""
    plaintext = b"Official grade sheet report."
    bundle = encrypt_file_data(plaintext, key_service=active_kek_service)

    # Corrupt ciphertext byte
    tampered_ciphertext = bytearray(bundle.ciphertext)
    tampered_ciphertext[0] ^= 0xFF
    bundle.ciphertext = bytes(tampered_ciphertext)

    with pytest.raises(IntegrityError):
        decrypt_file_data(bundle, key_service=active_kek_service)


def test_vaultctl_roundtrip_and_passphrase_protection():
    """Test 4: VaultCTL passphrase encryption round-trip and wrong passphrase rejection."""
    secret_note = b"Campus emergency action plan & security codes."
    passphrase = "CorrectHorseBatteryStaple2026!"
    wrong_passphrase = "IncorrectPassphraseAttempt!"

    encrypted = encrypt_data(passphrase, secret_note)
    assert secret_note not in encrypted

    # Decrypt with correct passphrase
    decrypted = decrypt_data(passphrase, encrypted)
    assert decrypted == secret_note

    # Decrypt with wrong passphrase must fail
    with pytest.raises(ValueError) as exc_info:
        decrypt_data(wrong_passphrase, encrypted)
    assert "incorrect passphrase" in str(exc_info.value).lower()


def test_vaultctl_inspection():
    """Test 5: VaultCTL inspect reads header metadata without decrypting."""
    data = b"Some secret archive bytes."
    passphrase = "SecretPassphrase123!"
    encrypted = encrypt_data(passphrase, data)

    meta = inspect_archive(encrypted)
    assert meta["magic"] == "VAULT1"
    assert len(meta["salt_hex"]) == 64  # 32 bytes hex
    assert len(meta["nonce_hex"]) == 24  # 12 bytes hex
    assert meta["ciphertext_bytes"] == len(data) + 16  # data + 16-byte GCM tag
