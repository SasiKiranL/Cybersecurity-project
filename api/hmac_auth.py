"""HMAC-SHA256 request authentication and integrity verification for CampusVault Sensor API.

Canonical request structure:
METHOD\n
PATH\n
TIMESTAMP\n
NONCE\n
SHA256(BODY)\n
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
from typing import Optional

from fastapi import HTTPException, Request, status

from api.nonce_cache import NonceCache
from audit.logger import AuditLogger
from audit.models import EventType, AuditResult
from keyservice.service import KeyService


def compute_canonical_string(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> str:
    """Construct the canonical request string."""
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_hash}\n"


def compute_hmac_signature(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
    secret: bytes,
) -> str:
    """Generate hex HMAC-SHA256 signature over the canonical request."""
    canonical = compute_canonical_string(method, path, timestamp, nonce, body)
    return hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


async def verify_hmac_request(
    request: Request,
    body: bytes,
    shared_secret: bytes,
    nonce_cache: NonceCache,
    key_service: Optional[KeyService] = None,
    tolerance_seconds: int = 300,
) -> dict:
    """Verify HMAC headers, timestamp skew, and nonce freshness.

    Returns verified header metadata on success.
    Raises HTTPException(401) on failure.
    """
    timestamp_hdr = request.headers.get("X-Timestamp")
    nonce_hdr = request.headers.get("X-Nonce")
    signature_hdr = request.headers.get("X-Signature")
    key_id_hdr = request.headers.get("X-Key-Id")

    db_path = getattr(request.app.state, "db_path", None)
    audit = AuditLogger(db_path=db_path)
    client_ip = request.client.host if request.client else "unknown"

    if not timestamp_hdr or not nonce_hdr or not signature_hdr:
        audit.log(
            event_type=EventType.AUTH.value,
            identity=client_ip,
            action="HMAC_AUTH_FAILED",
            result=AuditResult.FAILURE.value,
            detail="Missing required HMAC authentication headers",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: missing required security headers (X-Timestamp, X-Nonce, X-Signature).",
        )

    # 1. Verify timestamp skew
    try:
        req_dt = datetime.datetime.fromisoformat(timestamp_hdr)
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        if req_dt.tzinfo is None:
            req_dt = req_dt.replace(tzinfo=datetime.timezone.utc)

        skew = abs((now_dt - req_dt).total_seconds())
        if skew > tolerance_seconds:
            audit.log(
                event_type=EventType.AUTH.value,
                identity=client_ip,
                action="HMAC_TIMESTAMP_SKEW",
                result=AuditResult.DENIED.value,
                detail=f"Timestamp skew {skew:.1f}s exceeded tolerance {tolerance_seconds}s",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed: request timestamp is expired or out of allowed window.",
            )
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: invalid ISO 8601 timestamp format.",
        )

    # 2. Verify nonce (anti-replay)
    if not nonce_cache.check_and_add(nonce_hdr):
        audit.log(
            event_type=EventType.AUTH.value,
            identity=client_ip,
            action="HMAC_REPLAY_ATTACK",
            result=AuditResult.DENIED.value,
            detail=f"Replayed nonce detected: {nonce_hdr}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: replayed request nonce detected.",
        )

    # 3. Determine secret key
    secret = shared_secret
    if key_id_hdr and key_service:
        try:
            secret = key_service.get_key(key_id_hdr, caller="sensor_api")
        except Exception:
            audit.log(
                event_type=EventType.AUTH.value,
                identity=client_ip,
                action="HMAC_KEY_NOT_FOUND",
                result=AuditResult.FAILURE.value,
                detail=f"Key ID {key_id_hdr} not available",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed: invalid or revoked key ID.",
            )

    # 4. Verify signature using constant-time comparison
    expected_sig = compute_hmac_signature(
        method=request.method,
        path=request.url.path,
        timestamp=timestamp_hdr,
        nonce=nonce_hdr,
        body=body,
        secret=secret,
    )

    if not hmac.compare_digest(expected_sig, signature_hdr):
        audit.log(
            event_type=EventType.AUTH.value,
            identity=client_ip,
            action="HMAC_SIGNATURE_MISMATCH",
            result=AuditResult.FAILURE.value,
            detail="Signature verification mismatch (data altered or wrong secret)",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: cryptographic signature verification failed.",
        )

    return {
        "timestamp": timestamp_hdr,
        "nonce": nonce_hdr,
        "key_id": key_id_hdr,
    }
