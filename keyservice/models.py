"""Key service data models, enums and exception hierarchy."""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel


class KeyState(str, Enum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"
    DESTROYED = "destroyed"


class KeyPurpose(str, Enum):
    ENCRYPTION = "encryption"
    SIGNING = "signing"
    HMAC = "hmac"


class KeyAlgorithm(str, Enum):
    AES_256_GCM = "AES-256-GCM"
    ED25519 = "Ed25519"
    HMAC_SHA256 = "HMAC-SHA256"


class KeyServiceError(Exception):
    """Base exception for Key Service errors."""
    pass


class KeyNotFoundError(KeyServiceError):
    """Raised when the requested key ID does not exist."""
    pass


class KeyRevokedError(KeyServiceError):
    """Raised when attempting to access a key that has been revoked."""
    pass


class KeyDestroyedError(KeyServiceError):
    """Raised when attempting to access a key that has been destroyed."""
    pass


class KeyMetadata(BaseModel):
    id: str
    purpose: str
    algorithm: str
    state: str
    created_at: str
    rotated_at: Optional[str] = None
    revoked_at: Optional[str] = None
    replaced_by: Optional[str] = None
    created_by: str
    has_public_key: bool = False
