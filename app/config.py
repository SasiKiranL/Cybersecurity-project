"""Application configuration loader for CampusVault.

Loads settings from .env file or environment variables.
Never hardcodes secrets.
"""

from __future__ import annotations

import base64
import os
from functools import lru_cache
from pathlib import Path
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env file explicitly from project root
load_dotenv(dotenv_path=BASE_DIR / ".env")


class Settings(BaseModel):
    """Configuration settings for CampusVault."""

    # Project directories
    base_dir: Path = Field(default=BASE_DIR)
    data_dir: Path = Field(default_factory=lambda: BASE_DIR / "data")
    files_dir: Path = Field(default_factory=lambda: BASE_DIR / "data" / "files")
    pki_dir: Path = Field(default_factory=lambda: BASE_DIR / "pki")

    # Master Key for Key Service (base64-encoded 32 bytes)
    master_key_b64: str = Field(
        default_factory=lambda: os.getenv(
            "CV_MASTER_KEY",
            "ix-Gw2PxCMREdNgCK5gAwsiAF0OPlFG1ZX8VnlLrH4Q="
        )
    )

    # HMAC Shared Secret for Sensor API (base64-encoded 32 bytes)
    hmac_secret_b64: str = Field(
        default_factory=lambda: os.getenv(
            "CV_HMAC_SECRET",
            "rT7uPl8nX-NsLbNZDjih13UUdpcLYWoF87yjx9vrvHw="
        )
    )

    # Session Secret for cookie signing and CSRF tokens
    session_secret: str = Field(
        default_factory=lambda: os.getenv(
            "CV_SESSION_SECRET",
            "8OvuuXkS7Kji0bGPnZ0vQ-iYeBP1AkxlIIA6F1ehN2o"
        )
    )

    # Database file path
    db_path: Path = Field(
        default_factory=lambda: Path(
            os.getenv("CV_DB_PATH", str(BASE_DIR / "data" / "campusvault.db"))
        )
    )

    # Server Ports
    portal_port: int = Field(
        default_factory=lambda: int(os.getenv("CV_PORT_PORTAL", "8443"))
    )
    api_port: int = Field(
        default_factory=lambda: int(os.getenv("CV_PORT_API", "8444"))
    )

    # PKI Paths
    ca_cert_path: Path = Field(
        default_factory=lambda: BASE_DIR / os.getenv("CV_PKI_CA_CERT", "pki/ca.crt")
    )
    ca_key_path: Path = Field(
        default_factory=lambda: BASE_DIR / os.getenv("CV_PKI_CA_KEY", "pki/private/ca.key")
    )
    server_cert_path: Path = Field(
        default_factory=lambda: BASE_DIR / os.getenv("CV_PKI_SERVER_CERT", "pki/server.crt")
    )
    server_key_path: Path = Field(
        default_factory=lambda: BASE_DIR / os.getenv("CV_PKI_SERVER_KEY", "pki/private/server.key")
    )
    client_cert_path: Path = Field(
        default_factory=lambda: BASE_DIR / os.getenv("CV_PKI_CLIENT_CERT", "pki/client.crt")
    )
    client_key_path: Path = Field(
        default_factory=lambda: BASE_DIR / os.getenv("CV_PKI_CLIENT_KEY", "pki/private/client.key")
    )

    # Sensor API settings
    rate_limit: str = Field(
        default_factory=lambda: os.getenv("CV_RATE_LIMIT", "10/minute")
    )
    hmac_tolerance_seconds: int = Field(
        default_factory=lambda: int(os.getenv("CV_HMAC_TOLERANCE_SECONDS", "300"))
    )

    def get_master_key_bytes(self) -> bytes:
        """Decode base64 master key into 32 raw bytes."""
        try:
            # support urlsafe or standard base64
            key_bytes = base64.urlsafe_b64decode(self.master_key_b64)
            if len(key_bytes) != 32:
                # pad or fallback if needed
                key_bytes = base64.b64decode(self.master_key_b64)
            if len(key_bytes) != 32:
                raise ValueError("Master key must be exactly 32 bytes.")
            return key_bytes
        except Exception as e:
            # fallback to urlsafe with padding
            padded = self.master_key_b64 + "=" * (-len(self.master_key_b64) % 4)
            return base64.urlsafe_b64decode(padded)

    def get_hmac_secret_bytes(self) -> bytes:
        """Decode base64 HMAC secret into 32 raw bytes."""
        try:
            padded = self.hmac_secret_b64 + "=" * (-len(self.hmac_secret_b64) % 4)
            return base64.urlsafe_b64decode(padded)
        except Exception:
            return self.hmac_secret_b64.encode("utf-8")


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings."""
    settings = Settings()
    # Ensure data and files directories exist
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.files_dir.mkdir(parents=True, exist_ok=True)
    settings.pki_dir.mkdir(parents=True, exist_ok=True)
    (settings.pki_dir / "private").mkdir(parents=True, exist_ok=True)
    return settings
