"""Runner for CampusVault Web Portal with TLS."""

from __future__ import annotations

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

    print(f"[*] Starting CampusVault Web Portal on https://localhost:{settings.portal_port}...")

    uvicorn.run(
        "app.main:portal_app",
        host="127.0.0.1",
        port=settings.portal_port,
        ssl_keyfile=str(settings.server_key_path),
        ssl_certfile=str(settings.server_cert_path),
        reload=False,
    )


if __name__ == "__main__":
    main()
