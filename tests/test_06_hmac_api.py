"""Assessment 6 Tests: Secure API with HMAC, Nonce Anti-Replay, and Rate Limiting.

Verifies:
1. Legitimate HMAC-SHA256 signed requests are authenticated and accepted (201 Created).
2. Replayed request nonces are blocked (401 Unauthorized).
3. Expired or skewed timestamps outside the tolerance window are blocked (401 Unauthorized).
4. Tampering with request body invalidates the cryptographic signature (401 Unauthorized).
5. Exceeding the rate limit triggers HTTP 429 Too Many Requests with Retry-After header.
"""

from __future__ import annotations

import datetime
import json
import uuid
import pytest
from fastapi.testclient import TestClient

from api.hmac_auth import compute_hmac_signature
from api.main import create_api_app
from api.rate_limiter import SlidingWindowRateLimiter


@pytest.fixture
def hmac_secret() -> bytes:
    return b"TestHmacSecretSharedKey12345678"


@pytest.fixture
def test_client(temp_db_path: str, hmac_secret: bytes) -> tuple[TestClient, SlidingWindowRateLimiter]:
    limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
    app = create_api_app(
        db_path=temp_db_path,
        shared_secret=hmac_secret,
        rate_limiter=limiter,
    )
    client = TestClient(app)
    return client, limiter


def test_hmac_valid_request_accepted(test_client, hmac_secret: bytes):
    """Test 1: Valid canonical HMAC-SHA256 signed request returns 201 Created."""
    client, _ = test_client
    path = "/api/v1/telemetry"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    nonce = str(uuid.uuid4())
    payload = {
        "sensor_id": "sensor-test-01",
        "temperature": 22.4,
        "humidity": 50.1,
        "timestamp": timestamp,
    }
    body = json.dumps(payload).encode("utf-8")
    sig = compute_hmac_signature(
        method="POST",
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
        secret=hmac_secret,
    )

    headers = {
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": sig,
        "Content-Type": "application/json",
    }
    response = client.post(path, content=body, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "success"
    assert "reading_id" in data


def test_hmac_replay_attack_rejected(test_client, hmac_secret: bytes):
    """Test 2: Sending the exact same nonce a second time is rejected as a replay."""
    client, _ = test_client
    path = "/api/v1/telemetry"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    nonce = str(uuid.uuid4())
    payload = {
        "sensor_id": "sensor-test-02",
        "temperature": 21.0,
        "humidity": 48.0,
        "timestamp": timestamp,
    }
    body = json.dumps(payload).encode("utf-8")
    sig = compute_hmac_signature("POST", path, timestamp, nonce, body, hmac_secret)
    headers = {
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": sig,
        "Content-Type": "application/json",
    }

    # First attempt: succeeds
    res1 = client.post(path, content=body, headers=headers)
    assert res1.status_code == 201

    # Second attempt with same nonce: rejected
    res2 = client.post(path, content=body, headers=headers)
    assert res2.status_code == 401
    assert "replay" in res2.json()["detail"].lower()


def test_hmac_timestamp_skew_rejected(test_client, hmac_secret: bytes):
    """Test 3: Request with timestamp outside tolerance (e.g., 10 minutes ago) is rejected."""
    client, _ = test_client
    path = "/api/v1/telemetry"
    past_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)).isoformat()
    nonce = str(uuid.uuid4())
    payload = {
        "sensor_id": "sensor-test-03",
        "temperature": 20.0,
        "humidity": 45.0,
        "timestamp": past_time,
    }
    body = json.dumps(payload).encode("utf-8")
    sig = compute_hmac_signature("POST", path, past_time, nonce, body, hmac_secret)
    headers = {
        "X-Timestamp": past_time,
        "X-Nonce": nonce,
        "X-Signature": sig,
        "Content-Type": "application/json",
    }

    response = client.post(path, content=body, headers=headers)
    assert response.status_code == 401
    assert "timestamp" in response.json()["detail"].lower()


def test_hmac_body_tampering_rejected(test_client, hmac_secret: bytes):
    """Test 4: Modifying the request payload body invalidates signature and is rejected."""
    client, _ = test_client
    path = "/api/v1/telemetry"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    nonce = str(uuid.uuid4())
    original_payload = {
        "sensor_id": "sensor-test-04",
        "temperature": 18.5,
        "humidity": 40.0,
        "timestamp": timestamp,
    }
    body = json.dumps(original_payload).encode("utf-8")
    sig = compute_hmac_signature("POST", path, timestamp, nonce, body, hmac_secret)

    # Attacker alters temperature in transit without secret
    tampered_body = json.dumps({
        "sensor_id": "sensor-test-04",
        "temperature": 99.9,
        "humidity": 40.0,
        "timestamp": timestamp,
    }).encode("utf-8")

    headers = {
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": sig,
        "Content-Type": "application/json",
    }

    response = client.post(path, content=tampered_body, headers=headers)
    assert response.status_code == 401
    assert "signature" in response.json()["detail"].lower()


def test_rate_limiter_exceeded_triggers_429(test_client, hmac_secret: bytes):
    """Test 5: Exceeding rate limit triggers HTTP 429 with Retry-After header."""
    client, limiter = test_client
    path = "/api/v1/telemetry"

    # Make 5 requests (the limit for this fixture is max_requests=5)
    for i in range(5):
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        nonce = str(uuid.uuid4())
        body = json.dumps({"sensor_id": f"s-{i}", "temperature": 20.0, "humidity": 50.0, "timestamp": timestamp}).encode("utf-8")
        sig = compute_hmac_signature("POST", path, timestamp, nonce, body, hmac_secret)
        headers = {"X-Timestamp": timestamp, "X-Nonce": nonce, "X-Signature": sig, "Content-Type": "application/json"}
        res = client.post(path, content=body, headers=headers)
        assert res.status_code == 201

    # 6th request triggers rate limit
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    nonce = str(uuid.uuid4())
    body = json.dumps({"sensor_id": "s-overflow", "temperature": 20.0, "humidity": 50.0, "timestamp": timestamp}).encode("utf-8")
    sig = compute_hmac_signature("POST", path, timestamp, nonce, body, hmac_secret)
    headers = {"X-Timestamp": timestamp, "X-Nonce": nonce, "X-Signature": sig, "Content-Type": "application/json"}

    res = client.post(path, content=body, headers=headers)
    assert res.status_code == 429
    assert "Retry-After" in res.headers
    assert int(res.headers["Retry-After"]) > 0
