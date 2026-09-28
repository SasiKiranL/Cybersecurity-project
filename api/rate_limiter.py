"""In-memory sliding window rate limiter for CampusVault APIs.

Enforces requests-per-minute limits per client IP with Retry-After responses.
"""

from __future__ import annotations

import math
import threading
import time
from collections import defaultdict
from typing import Tuple

from fastapi import HTTPException, Request, status

from audit.logger import AuditLogger
from audit.models import EventType, AuditResult


class SlidingWindowRateLimiter:
    """Thread-safe sliding window rate limiter."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> Tuple[bool, int]:
        """Check if request from client_ip is within rate limit.

        Returns:
            (allowed: bool, retry_after: int)
        """
        now = time.time()
        with self._lock:
            timestamps = self._requests[client_ip]
            # Prune timestamps older than window
            cutoff = now - self.window_seconds
            self._requests[client_ip] = [ts for ts in timestamps if ts > cutoff]
            timestamps = self._requests[client_ip]

            if len(timestamps) >= self.max_requests:
                oldest = timestamps[0]
                retry_after = max(1, math.ceil(self.window_seconds - (now - oldest)))
                return False, retry_after

            timestamps.append(now)
            return True, 0

    def reset(self) -> None:
        """Reset all rate limit counters (useful for test suites)."""
        with self._lock:
            self._requests.clear()


# Default limiter: 10 requests per minute
default_limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=60)


def rate_limit_dependency(request: Request) -> None:
    """FastAPI dependency to enforce rate limit on endpoints."""
    limiter = getattr(request.app.state, "rate_limiter", default_limiter)
    client_ip = request.client.host if request.client else "127.0.0.1"

    allowed, retry_after = limiter.is_allowed(client_ip)
    if not allowed:
        db_path = getattr(request.app.state, "db_path", None)
        audit = AuditLogger(db_path=db_path)
        audit.log(
            event_type=EventType.SYSTEM.value,
            identity=client_ip,
            action="RATE_LIMIT_EXCEEDED",
            result=AuditResult.DENIED.value,
            detail=f"Rate limit exceeded on path '{request.url.path}'. Retry-After: {retry_after}s",
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please slow down.",
            headers={"Retry-After": str(retry_after)},
        )
