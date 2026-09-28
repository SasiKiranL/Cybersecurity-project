"""CampusVault Sensor Simulator.

Connects to the Sensor API over Mutual TLS (mTLS), computes HMAC-SHA256 signatures
with canonical request headers and nonces, and transmits sensor telemetry readings.
"""

from __future__ import annotations

import argparse
import datetime
import json
import random
import sys
import time
import uuid
from pathlib import Path

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import httpx

from api.hmac_auth import compute_hmac_signature
from app.config import get_settings


def send_telemetry_reading(
    sensor_id: str,
    temperature: float,
    humidity: float,
    api_url: str,
    secret: bytes,
    client_cert_path: Path,
    client_key_path: Path,
    ca_cert_path: Path,
) -> dict:
    """Send a single signed sensor reading over mTLS."""
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    nonce = str(uuid.uuid4())

    payload = {
        "sensor_id": sensor_id,
        "temperature": round(temperature, 2),
        "humidity": round(humidity, 2),
        "timestamp": timestamp,
    }
    body = json.dumps(payload).encode("utf-8")

    path = "/api/v1/telemetry"
    signature = compute_hmac_signature(
        method="POST",
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
        secret=secret,
    )

    headers = {
        "Content-Type": "application/json",
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }

    # Verify cert files exist
    cert = None
    if client_cert_path.exists() and client_key_path.exists():
        cert = (str(client_cert_path), str(client_key_path))

    verify_param = str(ca_cert_path) if ca_cert_path.exists() else False

    with httpx.Client(cert=cert, verify=verify_param, timeout=10.0) as client:
        response = client.post(f"{api_url}{path}", content=body, headers=headers)
        response.raise_for_status()
        return response.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="CampusVault Simulated Sensor Client")
    parser.add_argument("--iterations", type=int, default=3, help="Number of telemetry packets to send")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between telemetry packets")
    parser.add_argument("--sensor-id", default="sensor-lab-01", help="Sensor identifier")
    args = parser.parse_args()

    settings = get_settings()
    api_url = f"https://localhost:{settings.api_port}"
    secret = settings.get_hmac_secret_bytes()

    print(f"[*] Starting sensor simulator '{args.sensor_id}'...")
    print(f"[*] Target: {api_url}/api/v1/telemetry")
    print(f"[*] mTLS Client Cert: {settings.client_cert_path}")

    for i in range(1, args.iterations + 1):
        temp = 20.0 + random.uniform(-2.0, 5.0)
        hum = 45.0 + random.uniform(-5.0, 10.0)
        try:
            res = send_telemetry_reading(
                sensor_id=args.sensor_id,
                temperature=temp,
                humidity=hum,
                api_url=api_url,
                secret=secret,
                client_cert_path=settings.client_cert_path,
                client_key_path=settings.client_key_path,
                ca_cert_path=settings.ca_cert_path,
            )
            print(f"[+] [{i}/{args.iterations}] Reading transmitted: {temp:.1f}°C, {hum:.1f}% RH -> Status: {res.get('status')}")
        except Exception as e:
            print(f"[-] [{i}/{args.iterations}] Transmission failed: {e}", file=sys.stderr)

        if i < args.iterations:
            time.sleep(args.interval)

    print("[*] Sensor simulator finished successfully.")


if __name__ == "__main__":
    main()
