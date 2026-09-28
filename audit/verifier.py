"""Audit log integrity verifier.

Walks the full hash chain from genesis to head, re-calculating SHA-256 hashes
and verifying cryptographic continuity.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

from app.database import get_db_connection
from audit.logger import compute_canonical_hash
from audit.models import GENESIS_HASH


def verify_audit(db_path: Union[str, Path, None] = None) -> tuple[bool, list[str]]:
    """Verify integrity of the entire audit chain.

    Returns:
        (is_valid, list_of_errors)
    """
    errors: list[str] = []
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            """
            SELECT id, event_type, timestamp, identity, action, result, detail, prev_hash, record_hash
            FROM audit_log
            ORDER BY id ASC
            """
        )
        rows = cursor.fetchall()
        if not rows:
            return True, []

        last_hash = GENESIS_HASH

        for idx, row in enumerate(rows):
            record_id = row["id"]
            stored_prev_hash = row["prev_hash"]
            stored_record_hash = row["record_hash"]

            # 1. Verify prev_hash matches the previous record's hash (or genesis)
            if stored_prev_hash != last_hash:
                errors.append(
                    f"Chain break at record {record_id}: stored prev_hash "
                    f"'{stored_prev_hash[:16]}...' does not match expected '{last_hash[:16]}...'"
                )

            # 2. Recompute record_hash
            expected_record_hash = compute_canonical_hash(
                event_type=row["event_type"],
                timestamp=row["timestamp"],
                identity=row["identity"],
                action=row["action"],
                result=row["result"],
                detail=row["detail"],
                prev_hash=stored_prev_hash,
            )

            if stored_record_hash != expected_record_hash:
                errors.append(
                    f"Hash tampering detected at record {record_id}: stored hash "
                    f"'{stored_record_hash[:16]}...' != computed '{expected_record_hash[:16]}...'"
                )

            last_hash = stored_record_hash

        return len(errors) == 0, errors
    finally:
        conn.close()
