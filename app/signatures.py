"""Digital Signatures and verification using Ed25519 for CampusVault documents.

Features:
- Ed25519 digital signatures with SHA-256 content hashing
- Detached .sig file generation and parsing
- Verification before document download to ensure authenticity and integrity
- Audit logging of signing and verification events
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
from typing import Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from audit.models import EventType, AuditResult
from keyservice.service import KeyService


def sign_document(
    plaintext: bytes,
    signing_key_id: str,
    key_service: KeyService,
    signer_id: str = "system",
) -> dict:
    """Sign document content using Ed25519 private key from KeyService.

    Returns detached signature bundle dictionary.
    """
    # 1. Compute SHA-256 content hash
    content_hash = hashlib.sha256(plaintext).hexdigest()

    # 2. Retrieve private signing key bytes
    priv_bytes = key_service.get_key(signing_key_id, caller=signer_id)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

    # 3. Sign the content hash
    signature = private_key.sign(content_hash.encode("utf-8"))
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    bundle = {
        "signature_hex": signature.hex(),
        "signing_key_id": signing_key_id,
        "content_hash": content_hash,
        "signed_at": now,
        "signer_id": signer_id,
    }

    key_service.audit.log(
        event_type=EventType.DATA.value,
        identity=signer_id,
        action="DOCUMENT_SIGNED",
        result=AuditResult.SUCCESS.value,
        detail=f"signing_key_id={signing_key_id} hash={content_hash[:16]}...",
    )
    return bundle


def verify_document_signature(
    plaintext: bytes,
    signature_bundle: dict,
    key_service: KeyService,
    verifier_id: str = "system",
) -> bool:
    """Verify Ed25519 detached signature for the given document plaintext.

    Returns True if valid, False if invalid or tampered. Never raises.
    """
    try:
        content_hash = hashlib.sha256(plaintext).hexdigest()
        if content_hash != signature_bundle.get("content_hash"):
            key_service.audit.log(
                event_type=EventType.DATA.value,
                identity=verifier_id,
                action="SIGNATURE_VERIFICATION_FAILED",
                result=AuditResult.FAILURE.value,
                detail="Content hash mismatch (document modified)",
            )
            return False

        signing_key_id = signature_bundle.get("signing_key_id")
        pub_bytes = key_service.get_public_key(signing_key_id)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

        sig_bytes = bytes.fromhex(signature_bundle["signature_hex"])
        public_key.verify(sig_bytes, content_hash.encode("utf-8"))

        key_service.audit.log(
            event_type=EventType.DATA.value,
            identity=verifier_id,
            action="SIGNATURE_VERIFIED",
            result=AuditResult.SUCCESS.value,
            detail=f"signing_key_id={signing_key_id}",
        )
        return True
    except (InvalidSignature, Exception) as e:
        key_service.audit.log(
            event_type=EventType.DATA.value,
            identity=verifier_id,
            action="SIGNATURE_VERIFICATION_FAILED",
            result=AuditResult.FAILURE.value,
            detail=f"Verification failed: {type(e).__name__}",
        )
        return False


def save_detached_signature(bundle: dict, sig_path: Union[str, Path]) -> None:
    """Persist detached signature bundle to disk as formatted JSON."""
    path = Path(sig_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)


def load_detached_signature(sig_path: Union[str, Path]) -> dict:
    """Load detached signature bundle from disk."""
    path = Path(sig_path)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
