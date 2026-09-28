"""Master key encryption/decryption operations for Key Service storage at rest.

Uses AES-256-GCM authenticated encryption with unique random nonces per operation.
"""

from __future__ import annotations

import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_key_at_rest(
    master_key: bytes,
    plaintext_key: bytes,
    associated_data: Optional[bytes] = None,
) -> tuple[bytes, bytes]:
    """Encrypt key material with master key using AES-256-GCM.

    Returns:
        (ciphertext_with_tag, nonce)
    """
    if len(master_key) != 32:
        raise ValueError("Master key must be exactly 32 bytes (256 bits).")

    nonce = os.urandom(12)
    aesgcm = AESGCM(master_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_key, associated_data)
    return ciphertext, nonce


def decrypt_key_at_rest(
    master_key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Decrypt key material wrapped under master key using AES-256-GCM."""
    if len(master_key) != 32:
        raise ValueError("Master key must be exactly 32 bytes (256 bits).")

    aesgcm = AESGCM(master_key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)
