"""Runner for CampusVault Sensor API with mTLS."""

from __future__ import annotations

import ssl
import sys
from pathlib import Path

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import uvicorn
from app.config import get_settings


def main():
    settings = get_settings()

    print(f"[*] Starting CampusVault Sensor API on https://127.0.0.1:{settings.api_port} (mTLS enabled)...")

    # Uvicorn with mTLS
    uvicorn.run(
        "api.main:api_app",
        host="127.0.0.1",
        port=settings.api_port,
        ssl_keyfile=str(settings.server_key_path),
        ssl_certfile=str(settings.server_cert_path),
        ssl_ca_certs=str(settings.ca_cert_path),
        ssl_cert_reqs=ssl.CERT_OPTIONAL,  # or ssl.CERT_REQUIRED
        reload=False,
    )


if __name__ == "__main__":
    main()
