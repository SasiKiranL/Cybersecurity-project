"""FastAPI application for CampusVault Sensor Telemetry API.

Protected by:
- Mutual TLS (mTLS) at the transport layer
- HMAC-SHA256 request authentication and integrity at the application layer
- Nonce anti-replay verification
- Timestamp freshness window verification
- Client IP rate limiting
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Optional, Union

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field

from api.hmac_auth import verify_hmac_request
from api.nonce_cache import NonceCache
from api.rate_limiter import SlidingWindowRateLimiter, rate_limit_dependency
from app.config import get_settings
from app.database import db_session, get_db_connection
from audit.logger import AuditLogger
from audit.models import EventType, AuditResult
from keyservice.service import KeyService


class SensorReadingPayload(BaseModel):
    sensor_id: str = Field(..., min_length=1, max_length=50)
    temperature: float = Field(..., ge=-50.0, le=100.0)
    humidity: float = Field(..., ge=0.0, le=100.0)
    timestamp: str = Field(...)


def create_api_app(
    db_path: Union[str, Path, None] = None,
    shared_secret: Optional[bytes] = None,
    rate_limiter: Optional[SlidingWindowRateLimiter] = None,
    key_service: Optional[KeyService] = None,
) -> FastAPI:
    """Factory creating configured Sensor API application."""
    settings = get_settings()
    app = FastAPI(title="CampusVault Sensor API", version="1.0.0")

    secret = shared_secret if shared_secret is not None else settings.get_hmac_secret_bytes()
    limiter = rate_limiter or SlidingWindowRateLimiter(max_requests=10, window_seconds=60)
    nonce_cache = NonceCache(db_path=db_path, max_age_seconds=settings.hmac_tolerance_seconds)

    app.state.db_path = db_path
    app.state.shared_secret = secret
    app.state.rate_limiter = limiter
    app.state.nonce_cache = nonce_cache
    app.state.key_service = key_service

    @app.get("/api/v1/health")
    async def health_check():
        return {"status": "healthy", "service": "CampusVault Sensor API"}

    @app.post(
        "/api/v1/telemetry",
        dependencies=[Depends(rate_limit_dependency)],
        status_code=status.HTTP_201_CREATED,
    )
    async def receive_telemetry(request: Request):
        # 1. Read raw body bytes
        body = await request.body()

        # 2. Cryptographic HMAC and anti-replay verification
        auth_meta = await verify_hmac_request(
            request=request,
            body=body,
            shared_secret=app.state.shared_secret,
            nonce_cache=app.state.nonce_cache,
            key_service=app.state.key_service,
            tolerance_seconds=settings.hmac_tolerance_seconds,
        )

        # 3. Parse and validate JSON payload
        try:
            payload = SensorReadingPayload.model_validate_json(body)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid payload format: {e}",
            )

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 4. Insert into sensor_readings table
        with db_session(app.state.db_path) as conn:
            cursor = conn.execute(
                """
                INSERT INTO sensor_readings (sensor_id, temperature, humidity, timestamp, received_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    payload.sensor_id,
                    payload.temperature,
                    payload.humidity,
                    payload.timestamp,
                    now_iso,
                ),
            )
            reading_id = cursor.lastrowid

        # 5. Audit log
        audit = AuditLogger(db_path=app.state.db_path)
        audit.log(
            event_type=EventType.DATA.value,
            identity=payload.sensor_id,
            action="SENSOR_READING_RECEIVED",
            result=AuditResult.SUCCESS.value,
            detail=f"reading_id={reading_id} temp={payload.temperature} humidity={payload.humidity}",
        )

        return {
            "status": "success",
            "reading_id": reading_id,
            "received_at": now_iso,
        }

    @app.get(
        "/api/v1/telemetry",
        dependencies=[Depends(rate_limit_dependency)],
    )
    async def list_telemetry(limit: int = 50):
        conn = get_db_connection(app.state.db_path)
        try:
            cursor = conn.execute(
                """
                SELECT id, sensor_id, temperature, humidity, timestamp, received_at
                FROM sensor_readings
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    return app


api_app = create_api_app()
