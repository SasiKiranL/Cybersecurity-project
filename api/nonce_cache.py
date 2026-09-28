"""Nonce cache with in-memory fast lookup and SQLite persistence for replay protection.

Ensures no request signature can be replayed within the allowed timestamp window.
"""

from __future__ import annotations

import datetime
import threading
from pathlib import Path
from typing import Optional, Union

from app.database import db_session, get_db_connection


class NonceCache:
    """Thread-safe nonce cache with DB persistence and expiration."""

    def __init__(
        self,
        db_path: Union[str, Path, None] = None,
        max_age_seconds: int = 300,
    ) -> None:
        self.db_path = db_path
        self.max_age_seconds = max_age_seconds
        self._lock = threading.Lock()
        self._memory_set: set[str] = set()

    def check_and_add(self, nonce: str) -> bool:
        """Check if nonce has been seen before.

        Returns:
            True if nonce is fresh and was stored successfully.
            False if nonce is a replay.
        """
        if not nonce:
            return False

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self._lock:
            # 1. Fast in-memory check
            if nonce in self._memory_set:
                return False

            # 2. Database check and insert
            conn = get_db_connection(self.db_path)
            try:
                cursor = conn.execute("SELECT nonce FROM nonce_cache WHERE nonce = ?", (nonce,))
                if cursor.fetchone():
                    self._memory_set.add(nonce)
                    return False
            finally:
                conn.close()

            # Insert into database
            try:
                with db_session(self.db_path) as conn:
                    conn.execute(
                        "INSERT INTO nonce_cache (nonce, received_at) VALUES (?, ?)",
                        (nonce, now),
                    )
                self._memory_set.add(nonce)
                return True
            except Exception:
                # Concurrent insert race or DB constraint
                return False

    def prune(self) -> int:
        """Prune nonces older than max_age_seconds from both database and memory."""
        cutoff = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(seconds=self.max_age_seconds)
        ).isoformat()

        with self._lock:
            with db_session(self.db_path) as conn:
                cursor = conn.execute(
                    "DELETE FROM nonce_cache WHERE received_at < ?",
                    (cutoff,),
                )
                deleted = cursor.rowcount

            # Re-sync memory set with remaining valid nonces
            conn = get_db_connection(self.db_path)
            try:
                cursor = conn.execute("SELECT nonce FROM nonce_cache")
                self._memory_set = {row["nonce"] for row in cursor.fetchall()}
            finally:
                conn.close()

            return deleted
