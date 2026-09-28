"""Audit log data models and constants."""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

GENESIS_HASH = "0" * 64


class EventType(str, Enum):
    AUTH = "AUTH"
    KEY = "KEY"
    ACCESS = "ACCESS"
    DATA = "DATA"
    SYSTEM = "SYSTEM"


class AuditResult(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"


class AuditEvent(BaseModel):
    id: Optional[int] = None
    event_type: str
    timestamp: str
    identity: str
    action: str
    result: str
    detail: str = Field(default="")
    prev_hash: str
    record_hash: str
