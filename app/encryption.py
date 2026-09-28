"""Authenticated File Encryption using AES-256-GCM and Envelope Encryption.

Features:
- Envelope encryption: random per-file DEK wrapped by KeyService KEK
- AES-256-GCM authenticated encryption (ensures confidentiality and integrity)
- Random 12-byte nonces for both DEK wrapping and file encryption (never reused)
- Serialization to/from tamper-evident binary file format
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Optional, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from audit.logger import AuditLogger
from audit.models import EventType, AuditResult
from keyservice.service import KeyService
from keyservice.models import KeyPurpose

MAGIC_HEADER = b"CVENC1"


class EncryptionError(Exception):
    """Base encryption error."""
    pass


class IntegrityError(EncryptionError):
    """Raised when ciphertext tampering or authentication tag verification fails."""
    pass


class EncryptedBundle:
    """Represents an envelope-encrypted payload."""

    def __init__(
        self,
        kek_id: str,
        dek_nonce: bytes,
        wrapped_dek: bytes,
        data_nonce: bytes,
        ciphertext: bytes,
    ) -> None:
        self.kek_id = kek_id
        self.dek_nonce = dek_nonce
        self.wrapped_dek = wrapped_dek
        self.data_nonce = data_nonce
        self.ciphertext = ciphertext

    def serialize(self) -> bytes:
        """Serialize bundle into binary format.

        Format:
        [MAGIC(6)]
        [kek_id_len(2)] [kek_id]
        [dek_nonce(12)]
        [wrapped_dek_len(2)] [wrapped_dek]
        [data_nonce(12)]
        [ciphertext]
        """
        kek_bytes = self.kek_id.encode("utf-8")
        header = (
            MAGIC_HEADER
            + struct.pack(">H", len(kek_bytes))
            + kek_bytes
            + self.dek_nonce
            + struct.pack(">H", len(self.wrapped_dek))
            + self.wrapped_dek
            + self.data_nonce
        )
        return header + self.ciphertext

    @classmethod
    def deserialize(cls, data: bytes) -> "EncryptedBundle":
        """Parse binary data into an EncryptedBundle."""
        if len(data) < len(MAGIC_HEADER) + 2 + 12 + 2 + 12:
            raise IntegrityError("Corrupted file: header too short.")

        if not data.startswith(MAGIC_HEADER):
            raise IntegrityError("Invalid file header: magic mismatch.")

        offset = len(MAGIC_HEADER)
        (kek_id_len,) = struct.unpack_from(">H", data, offset)
        offset += 2

        kek_id = data[offset : offset + kek_id_len].decode("utf-8")
        offset += kek_id_len

        dek_nonce = data[offset : offset + 12]
        offset += 12

        (wrapped_dek_len,) = struct.unpack_from(">H", data, offset)
        offset += 2

        wrapped_dek = data[offset : offset + wrapped_dek_len]
        offset += wrapped_dek_len

        data_nonce = data[offset : offset + 12]
        offset += 12

        ciphertext = data[offset:]
        return cls(
            kek_id=kek_id,
            dek_nonce=dek_nonce,
            wrapped_dek=wrapped_dek,
            data_nonce=data_nonce,
            ciphertext=ciphertext,
        )


def encrypt_file_data(
    plaintext: bytes,
    key_service: KeyService,
    uploader_id: str = "system",
    associated_data: Optional[bytes] = None,
) -> EncryptedBundle:
    """Envelope encrypt plaintext data:
    1. Generate a random 256-bit DEK.
    2. Encrypt plaintext with AES-256-GCM using the DEK and a 12-byte random nonce.
    3. Retrieve the active KEK from key_service.
    4. Wrap the DEK with AES-256-GCM under the KEK.
    5. Return the EncryptedBundle.
    """
    # 1. Generate DEK
    dek = os.urandom(32)
    data_nonce = os.urandom(12)

    # 2. Encrypt data with DEK
    aesgcm_dek = AESGCM(dek)
    ciphertext = aesgcm_dek.encrypt(data_nonce, plaintext, associated_data)

    # 3. Get active KEK
    kek_meta = key_service.get_active_key(KeyPurpose.ENCRYPTION)
    kek_bytes = key_service.get_key(kek_meta.id, caller=uploader_id)

    # 4. Wrap DEK under KEK
    dek_nonce = os.urandom(12)
    aesgcm_kek = AESGCM(kek_bytes)
    wrapped_dek = aesgcm_kek.encrypt(dek_nonce, dek, kek_meta.id.encode("utf-8"))

    bundle = EncryptedBundle(
        kek_id=kek_meta.id,
        dek_nonce=dek_nonce,
        wrapped_dek=wrapped_dek,
        data_nonce=data_nonce,
        ciphertext=ciphertext,
    )

    key_service.audit.log(
        event_type=EventType.DATA.value,
        identity=uploader_id,
        action="FILE_ENCRYPTED",
        result=AuditResult.SUCCESS.value,
        detail=f"kek_id={kek_meta.id} bytes_len={len(plaintext)}",
    )
    return bundle


def decrypt_file_data(
    bundle: EncryptedBundle,
    key_service: KeyService,
    caller_id: str = "system",
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Unwrap DEK using KEK from KeyService and decrypt authenticated ciphertext."""
    try:
        # Retrieve KEK
        kek_bytes = key_service.get_key(bundle.kek_id, caller=caller_id)
        aesgcm_kek = AESGCM(kek_bytes)

        # Unwrap DEK
        dek = aesgcm_kek.decrypt(
            bundle.dek_nonce,
            bundle.wrapped_dek,
            bundle.kek_id.encode("utf-8"),
        )

        # Decrypt ciphertext
        aesgcm_dek = AESGCM(dek)
        plaintext = aesgcm_dek.decrypt(bundle.data_nonce, bundle.ciphertext, associated_data)

        key_service.audit.log(
            event_type=EventType.DATA.value,
            identity=caller_id,
            action="FILE_DECRYPTED",
            result=AuditResult.SUCCESS.value,
            detail=f"kek_id={bundle.kek_id} plaintext_len={len(plaintext)}",
        )
        return plaintext
    except (InvalidTag, Exception) as e:
        key_service.audit.log(
            event_type=EventType.DATA.value,
            identity=caller_id,
            action="FILE_DECRYPT_FAILED",
            result=AuditResult.FAILURE.value,
            detail=f"kek_id={bundle.kek_id} error={type(e).__name__}",
        )
        raise IntegrityError(
            "File decryption failed: authentication tag mismatch or corrupted data."
        )
