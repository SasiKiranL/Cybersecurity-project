"""Cryptographic Key Management Service for CampusVault.

Manages cryptographic keys through their complete lifecycle:
Generation, Storage (encrypted at rest), Usage, Rotation, Revocation, Destruction.
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import uuid
from pathlib import Path
from typing import Optional, Union, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.database import db_session, get_db_connection
from audit.logger import AuditLogger
from audit.models import EventType, AuditResult
from keyservice.models import (
    KeyAlgorithm,
    KeyDestroyedError,
    KeyMetadata,
    KeyNotFoundError,
    KeyPurpose,
    KeyRevokedError,
    KeyServiceError,
    KeyState,
)
from keyservice.store import decrypt_key_at_rest, encrypt_key_at_rest


def _utcnow_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class KeyService:
    """Manages system cryptographic keys."""

    def __init__(
        self,
        master_key: bytes,
        db_path: Union[str, Path, None] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        if len(master_key) != 32:
            raise ValueError("Master key must be exactly 32 bytes.")
        self.master_key = master_key
        self.db_path = db_path
        self.audit = audit_logger or AuditLogger(db_path=db_path)

    def generate_key(
        self,
        purpose: Union[str, KeyPurpose],
        algorithm: Union[str, KeyAlgorithm],
        created_by: str = "system",
    ) -> str:
        """Generate a new key, encrypt it with the master key, and persist it."""
        purpose_val = purpose.value if isinstance(purpose, KeyPurpose) else str(purpose)
        algo_val = algorithm.value if isinstance(algorithm, KeyAlgorithm) else str(algorithm)

        raw_key: bytes
        public_bytes: Optional[bytes] = None

        if algo_val == KeyAlgorithm.AES_256_GCM.value:
            raw_key = os.urandom(32)
        elif algo_val == KeyAlgorithm.ED25519.value:
            private_key = ed25519.Ed25519PrivateKey.generate()
            raw_key = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            public_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        elif algo_val == KeyAlgorithm.HMAC_SHA256.value:
            raw_key = os.urandom(32)
        else:
            raise KeyServiceError(f"Unsupported algorithm: {algo_val}")

        key_id = str(uuid.uuid4())
        encrypted_material, nonce = encrypt_key_at_rest(
            master_key=self.master_key,
            plaintext_key=raw_key,
            associated_data=key_id.encode("utf-8"),
        )
        created_at = _utcnow_iso()

        with db_session(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO crypto_keys
                (id, purpose, algorithm, state, encrypted_key_material, key_nonce,
                 public_key_material, created_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key_id,
                    purpose_val,
                    algo_val,
                    KeyState.ACTIVE.value,
                    encrypted_material,
                    nonce,
                    public_bytes,
                    created_at,
                    created_by,
                ),
            )

        self.audit.log(
            event_type=EventType.KEY.value,
            identity=created_by,
            action="KEY_GENERATED",
            result=AuditResult.SUCCESS.value,
            detail=f"key_id={key_id} purpose={purpose_val} algorithm={algo_val}",
        )
        return key_id

    def get_key(self, key_id: str, caller: str = "system") -> bytes:
        """Unwrap and return raw key bytes.

        Raises KeyNotFoundError, KeyRevokedError, or KeyDestroyedError.
        """
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.execute(
                """
                SELECT id, purpose, algorithm, state, encrypted_key_material, key_nonce
                FROM crypto_keys
                WHERE id = ?
                """,
                (key_id,),
            )
            row = cursor.fetchone()
            if not row:
                self.audit.log(
                    event_type=EventType.KEY.value,
                    identity=caller,
                    action="KEY_ACCESS_FAILED",
                    result=AuditResult.FAILURE.value,
                    detail=f"key_id={key_id} reason=not_found",
                )
                raise KeyNotFoundError(f"Key '{key_id}' not found.")

            state = row["state"]
            if state == KeyState.REVOKED.value:
                self.audit.log(
                    event_type=EventType.KEY.value,
                    identity=caller,
                    action="KEY_ACCESS_DENIED",
                    result=AuditResult.DENIED.value,
                    detail=f"key_id={key_id} reason=revoked",
                )
                raise KeyRevokedError(f"Key '{key_id}' has been revoked.")

            if state == KeyState.DESTROYED.value:
                self.audit.log(
                    event_type=EventType.KEY.value,
                    identity=caller,
                    action="KEY_ACCESS_DENIED",
                    result=AuditResult.DENIED.value,
                    detail=f"key_id={key_id} reason=destroyed",
                )
                raise KeyDestroyedError(f"Key '{key_id}' has been destroyed.")

            plaintext_key = decrypt_key_at_rest(
                master_key=self.master_key,
                ciphertext=row["encrypted_key_material"],
                nonce=row["key_nonce"],
                associated_data=key_id.encode("utf-8"),
            )

            self.audit.log(
                event_type=EventType.KEY.value,
                identity=caller,
                action="KEY_ACCESSED",
                result=AuditResult.SUCCESS.value,
                detail=f"key_id={key_id}",
            )
            return plaintext_key
        finally:
            conn.close()

    def get_public_key(self, key_id: str) -> bytes:
        """Return public key bytes for an asymmetric key."""
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.execute(
                "SELECT state, public_key_material FROM crypto_keys WHERE id = ?",
                (key_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise KeyNotFoundError(f"Key '{key_id}' not found.")
            if row["state"] == KeyState.DESTROYED.value:
                raise KeyDestroyedError(f"Key '{key_id}' has been destroyed.")
            if row["public_key_material"] is None:
                raise KeyServiceError(f"Key '{key_id}' has no public key material.")
            return bytes(row["public_key_material"])
        finally:
            conn.close()

    def rotate_key(self, old_key_id: str, caller: str = "system") -> str:
        """Retire the old key and create a replacement with the same purpose and algorithm."""
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.execute(
                "SELECT purpose, algorithm, state FROM crypto_keys WHERE id = ?",
                (old_key_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise KeyNotFoundError(f"Key '{old_key_id}' not found.")
            if row["state"] in (KeyState.REVOKED.value, KeyState.DESTROYED.value):
                raise KeyServiceError(f"Cannot rotate key in state '{row['state']}'.")
            purpose = row["purpose"]
            algorithm = row["algorithm"]
        finally:
            conn.close()

        # Generate replacement key
        new_key_id = self.generate_key(purpose=purpose, algorithm=algorithm, created_by=caller)
        rotated_at = _utcnow_iso()

        with db_session(self.db_path) as conn:
            conn.execute(
                """
                UPDATE crypto_keys
                SET state = ?, rotated_at = ?, replaced_by = ?
                WHERE id = ?
                """,
                (KeyState.RETIRED.value, rotated_at, new_key_id, old_key_id),
            )

        self.audit.log(
            event_type=EventType.KEY.value,
            identity=caller,
            action="KEY_ROTATED",
            result=AuditResult.SUCCESS.value,
            detail=f"old_key_id={old_key_id} new_key_id={new_key_id}",
        )
        return new_key_id

    def revoke_key(self, key_id: str, caller: str = "system") -> None:
        """Mark a key as revoked, preventing future unwrapping."""
        revoked_at = _utcnow_iso()
        with db_session(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT state FROM crypto_keys WHERE id = ?",
                (key_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise KeyNotFoundError(f"Key '{key_id}' not found.")

            conn.execute(
                """
                UPDATE crypto_keys
                SET state = ?, revoked_at = ?
                WHERE id = ?
                """,
                (KeyState.REVOKED.value, revoked_at, key_id),
            )

        self.audit.log(
            event_type=EventType.KEY.value,
            identity=caller,
            action="KEY_REVOKED",
            result=AuditResult.SUCCESS.value,
            detail=f"key_id={key_id}",
        )

    def destroy_key(self, key_id: str, caller: str = "system") -> None:
        """Cryptographically sanitize key material and mark as destroyed."""
        with db_session(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT id FROM crypto_keys WHERE id = ?",
                (key_id,),
            )
            if not cursor.fetchone():
                raise KeyNotFoundError(f"Key '{key_id}' not found.")

            # Zero-out encrypted key material and nonce
            conn.execute(
                """
                UPDATE crypto_keys
                SET state = ?, encrypted_key_material = ?, key_nonce = ?
                WHERE id = ?
                """,
                (KeyState.DESTROYED.value, b"\x00" * 32, b"\x00" * 12, key_id),
            )

        self.audit.log(
            event_type=EventType.KEY.value,
            identity=caller,
            action="KEY_DESTROYED",
            result=AuditResult.SUCCESS.value,
            detail=f"key_id={key_id}",
        )

    def get_active_key(self, purpose: Union[str, KeyPurpose]) -> KeyMetadata:
        """Find the currently active key for the specified purpose."""
        purpose_val = purpose.value if isinstance(purpose, KeyPurpose) else str(purpose)
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.execute(
                """
                SELECT id, purpose, algorithm, state, created_at, rotated_at, revoked_at,
                       replaced_by, created_by, public_key_material
                FROM crypto_keys
                WHERE purpose = ? AND state = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (purpose_val, KeyState.ACTIVE.value),
            )
            row = cursor.fetchone()
            if not row:
                raise KeyNotFoundError(f"No active key found for purpose '{purpose_val}'.")
            return KeyMetadata(
                id=row["id"],
                purpose=row["purpose"],
                algorithm=row["algorithm"],
                state=row["state"],
                created_at=row["created_at"],
                rotated_at=row["rotated_at"],
                revoked_at=row["revoked_at"],
                replaced_by=row["replaced_by"],
                created_by=row["created_by"],
                has_public_key=row["public_key_material"] is not None,
            )
        finally:
            conn.close()

    def list_keys(self, purpose: Optional[Union[str, KeyPurpose]] = None) -> list[KeyMetadata]:
        """List metadata for all keys, never exposing raw key material."""
        conn = get_db_connection(self.db_path)
        try:
            query = """
                SELECT id, purpose, algorithm, state, created_at, rotated_at, revoked_at,
                       replaced_by, created_by, public_key_material
                FROM crypto_keys
            """
            params: list[Any] = []
            if purpose:
                purpose_val = purpose.value if isinstance(purpose, KeyPurpose) else str(purpose)
                query += " WHERE purpose = ?"
                params.append(purpose_val)

            query += " ORDER BY created_at DESC"
            cursor = conn.execute(query, params)
            return [
                KeyMetadata(
                    id=row["id"],
                    purpose=row["purpose"],
                    algorithm=row["algorithm"],
                    state=row["state"],
                    created_at=row["created_at"],
                    rotated_at=row["rotated_at"],
                    revoked_at=row["revoked_at"],
                    replaced_by=row["replaced_by"],
                    created_by=row["created_by"],
                    has_public_key=row["public_key_material"] is not None,
                )
                for row in cursor.fetchall()
            ]
        finally:
            conn.close()

    def backup(self, backup_path: Union[str, Path], caller: str = "system") -> None:
        """Export encrypted key store records to a file."""
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.execute("SELECT * FROM crypto_keys")
            records = []
            for row in cursor.fetchall():
                rec = dict(row)
                rec["encrypted_key_material"] = base64.b64encode(
                    rec["encrypted_key_material"]
                ).decode("ascii")
                rec["key_nonce"] = base64.b64encode(rec["key_nonce"]).decode("ascii")
                if rec["public_key_material"]:
                    rec["public_key_material"] = base64.b64encode(
                        rec["public_key_material"]
                    ).decode("ascii")
                records.append(rec)

            out_path = Path(backup_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "keys": records}, f, indent=2)

            self.audit.log(
                event_type=EventType.KEY.value,
                identity=caller,
                action="KEY_BACKUP",
                result=AuditResult.SUCCESS.value,
                detail=f"keys_count={len(records)} destination={out_path.name}",
            )
        finally:
            conn.close()

    def restore(self, backup_path: Union[str, Path], caller: str = "system") -> None:
        """Restore encrypted key store records from a backup file."""
        in_path = Path(backup_path)
        with open(in_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        records = data.get("keys", [])
        with db_session(self.db_path) as conn:
            for rec in records:
                enc_mat = base64.b64decode(rec["encrypted_key_material"])
                nonce = base64.b64decode(rec["key_nonce"])
                pub_mat = (
                    base64.b64decode(rec["public_key_material"])
                    if rec.get("public_key_material")
                    else None
                )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO crypto_keys
                    (id, purpose, algorithm, state, encrypted_key_material, key_nonce,
                     public_key_material, created_at, rotated_at, revoked_at, replaced_by, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rec["id"],
                        rec["purpose"],
                        rec["algorithm"],
                        rec["state"],
                        enc_mat,
                        nonce,
                        pub_mat,
                        rec["created_at"],
                        rec.get("rotated_at"),
                        rec.get("revoked_at"),
                        rec.get("replaced_by"),
                        rec.get("created_by", "system"),
                    ),
                )

        self.audit.log(
            event_type=EventType.KEY.value,
            identity=caller,
            action="KEY_RESTORE",
            result=AuditResult.SUCCESS.value,
            detail=f"keys_count={len(records)} source={in_path.name}",
        )
