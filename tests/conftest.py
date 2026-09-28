"""Shared pytest fixtures for CampusVault test suite."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Generator
import pytest

from app.database import init_db
from audit.logger import AuditLogger
from keyservice.service import KeyService


@pytest.fixture
def temp_db_path(tmp_path: Path) -> str:
    """Create a temporary SQLite database initialized with schema and seed roles."""
    db_file = tmp_path / "test_campusvault.db"
    init_db(db_file)
    return str(db_file)


@pytest.fixture
def master_key() -> bytes:
    """32-byte test master key."""
    return b"\x01" * 32


@pytest.fixture
def audit_logger(temp_db_path: str) -> AuditLogger:
    """Initialized AuditLogger pointing to temporary database."""
    return AuditLogger(db_path=temp_db_path)


@pytest.fixture
def key_service(master_key: bytes, temp_db_path: str, audit_logger: AuditLogger) -> KeyService:
    """Initialized KeyService with temporary DB and audit logger."""
    return KeyService(master_key=master_key, db_path=temp_db_path, audit_logger=audit_logger)
