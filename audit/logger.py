"""Hash-chained, tamper-evident audit logger for CampusVault.

Every log entry includes the SHA-256 hash of the previous record,
creating an append-only verifiable cryptographic chain.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import sys
import threading
from pathlib import Path
from typing import Optional, Union, Any

from app.database import db_session, get_db_connection
from audit.models import AuditEvent, GENESIS_HASH

# Sensitive patterns that must never appear in audit details
SENSITIVE_PATTERNS = [
    re.compile(r"password['\"\s:=]+([^\s,'\"}]+)", re.IGNORECASE),
    re.compile(r"secret['\"\s:=]+([^\s,'\"}]+)", re.IGNORECASE),
    re.compile(r"token['\"\s:=]+([^\s,'\"}]+)", re.IGNORECASE),
    re.compile(r"master_key['\"\s:=]+([^\s,'\"}]+)", re.IGNORECASE),
    re.compile(r"private_key['\"\s:=]+([^\s,'\"}]+)", re.IGNORECASE),
]


def scrub_detail(detail: str) -> str:
    """Scrub sensitive information like passwords and tokens from log details."""
    scrubbed = str(detail)
    for pattern in SENSITIVE_PATTERNS:
        scrubbed = pattern.sub("[REDACTED]", scrubbed)
    return scrubbed


def compute_canonical_hash(
    event_type: str,
    timestamp: str,
    identity: str,
    action: str,
    result: str,
    detail: str,
    prev_hash: str,
) -> str:
    """Compute the deterministic SHA-256 hash of record fields."""
    canonical_dict = {
        "action": action,
        "detail": detail,
        "event_type": event_type,
        "identity": identity,
        "prev_hash": prev_hash,
        "result": result,
        "timestamp": timestamp,
    }
    canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class AuditLogger:
    """Thread-safe, hash-chained audit logger."""

    def __init__(self, db_path: Union[str, Path, None] = None) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()

    def log(
        self,
        event_type: str,
        identity: str,
        action: str,
        result: str,
        detail: str = "",
    ) -> Optional[AuditEvent]:
        """Append an audit record to the hash chain.

        Returns the created AuditEvent or None if a DB error occurred.
        Never raises exceptions to callers — fails safely.
        """
        clean_detail = scrub_detail(detail)
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self._lock:
            try:
                with db_session(self.db_path) as conn:
                    # Find previous record to chain hashes
                    cursor = conn.execute(
                        "SELECT record_hash FROM audit_log ORDER BY id DESC LIMIT 1"
                    )
                    row = cursor.fetchone()
                    prev_hash = row["record_hash"] if row else GENESIS_HASH

                    # Compute current record's hash
                    record_hash = compute_canonical_hash(
                        event_type=event_type,
                        timestamp=timestamp,
                        identity=identity,
                        action=action,
                        result=result,
                        detail=clean_detail,
                        prev_hash=prev_hash,
                    )

                    cursor = conn.execute(
                        """
                        INSERT INTO audit_log
                        (event_type, timestamp, identity, action, result, detail, prev_hash, record_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event_type,
                            timestamp,
                            identity,
                            action,
                            result,
                            clean_detail,
                            prev_hash,
                            record_hash,
                        ),
                    )
                    inserted_id = cursor.lastrowid

                    return AuditEvent(
                        id=inserted_id,
                        event_type=event_type,
                        timestamp=timestamp,
                        identity=identity,
                        action=action,
                        result=result,
                        detail=clean_detail,
                        prev_hash=prev_hash,
                        record_hash=record_hash,
                    )
            except Exception as e:
                # Log-write failure: warn to stderr, never crash application
                print(f"[AUDIT WARNING] Failed to write audit log: {e}", file=sys.stderr)
                return None

    def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Retrieve recent audit events for admin inspection."""
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.execute(
                """
                SELECT id, event_type, timestamp, identity, action, result, detail, prev_hash, record_hash
                FROM audit_log
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
