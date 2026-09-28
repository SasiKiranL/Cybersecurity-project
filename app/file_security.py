"""File upload security validator for CampusVault.

Implements Defense-in-Depth input sanitization:
1. Strict filename sanitization (prevent path traversal and control chars).
2. Extension allowlist check (.pdf, .txt, .docx, .csv, .md, .json, .png, .jpg).
3. Maximum file size enforcement (prevent DoS).
4. Magic bytes / header inspection (prevent MIME spoofing / polyglot attacks).
"""

from __future__ import annotations

import re
from pathlib import Path

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 Megabytes

ALLOWED_EXTENSIONS = {
    ".pdf",
    ".txt",
    ".docx",
    ".csv",
    ".md",
    ".json",
    ".png",
    ".jpg",
    ".jpeg",
}

# Magic signatures for binary file validation
MAGIC_SIGNATURES = {
    ".pdf": [b"%PDF-"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".docx": [b"PK\x03\x04"],  # Office OpenXML ZIP container
}


class FileSecurityError(Exception):
    """Raised when an uploaded file violates security policy."""


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent directory traversal and special character injection."""
    if not filename or not filename.strip():
        return "unnamed_document.txt"

    # Strip directory components (Windows and POSIX)
    cleaned = Path(filename).name
    # Remove any null bytes or control characters
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", cleaned)
    # Whitelist characters: alphanumeric, hyphen, underscore, dot
    cleaned = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", cleaned)
    # Prevent leading dots (hidden files)
    cleaned = cleaned.lstrip(".")
    if not cleaned:
        return "document.txt"
    return cleaned


def validate_uploaded_file(filename: str, content: bytes) -> str:
    """Validate uploaded file for size, safe name, allowed extension, and magic header.

    Returns the sanitized safe filename on success, or raises FileSecurityError.
    """
    if not content or len(content) == 0:
        raise FileSecurityError("Security Rejection: Uploaded file is empty.")

    if len(content) > MAX_FILE_SIZE:
        raise FileSecurityError(
            f"Security Rejection: File size ({len(content)} bytes) exceeds 5MB limit."
        )

    safe_name = sanitize_filename(filename)
    ext = Path(safe_name).suffix.lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise FileSecurityError(
            f"Security Rejection: File extension '{ext}' is not permitted. "
            f"Allowed types: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )

    # Magic byte verification for binary formats
    if ext in MAGIC_SIGNATURES:
        signatures = MAGIC_SIGNATURES[ext]
        if not any(content.startswith(sig) for sig in signatures):
            raise FileSecurityError(
                f"Security Rejection: File contents do not match expected magic bytes for {ext}."
            )
    else:
        # For text-based formats (.txt, .csv, .md, .json), verify valid UTF-8 and no null bytes
        if b"\x00" in content:
            raise FileSecurityError(
                "Security Rejection: Binary / null-byte payload detected in text document."
            )
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            raise FileSecurityError(
                "Security Rejection: Text document contains invalid UTF-8 encoding."
            )

    return safe_name
