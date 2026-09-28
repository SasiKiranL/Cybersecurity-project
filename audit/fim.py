"""Cryptographic File Integrity Monitor (FIM) for CampusVault.

Provides continuous tamper-evidence for critical application modules,
PKI certificates, and security configurations using SHA-256 baseline hashing.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

# Relative paths of high-security assets to monitor
MONITORED_TARGETS = [
    "requirements.txt",
    ".env.example",
    "pki/generate_pki.py",
    "pki/certs/ca.crt",
    "pki/certs/server.crt",
    "app/auth.py",
    "app/encryption.py",
    "app/signatures.py",
    "app/rbac.py",
    "app/session.py",
    "app/file_security.py",
    "audit/logger.py",
    "audit/verifier.py",
    "keyservice/service.py",
]


def compute_file_sha256(file_path: Path) -> str:
    """Compute standard SHA-256 digest of file contents."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def generate_fim_baseline(
    base_dir: Union[str, Path],
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, str]:
    """Generate SHA-256 cryptographic baseline hashes for monitored files."""
    base = Path(base_dir).resolve()
    hashes: Dict[str, str] = {}

    for rel_path in MONITORED_TARGETS:
        full_path = base / rel_path
        if full_path.exists() and full_path.is_file():
            hashes[rel_path] = compute_file_sha256(full_path)

    baseline_data = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "SHA-256",
        "file_count": len(hashes),
        "files": hashes,
    }

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(baseline_data, indent=2), encoding="utf-8")

    return hashes


def verify_fim(
    base_dir: Union[str, Path],
    baseline_path: Optional[Union[str, Path]] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> Tuple[bool, List[str]]:
    """Compare active files against baseline cryptographic hashes.

    Returns:
        (is_intact, list_of_findings)
    """
    base = Path(base_dir).resolve()
    target_baseline = (
        Path(baseline_path) if baseline_path else base / "data" / "fim_baseline.json"
    )

    if not target_baseline.exists():
        # Auto-initialize baseline if not present
        generate_fim_baseline(base, target_baseline)
        return True, ["FIM baseline newly established with zero violations."]

    try:
        data = json.loads(target_baseline.read_text(encoding="utf-8"))
        baseline_files = data.get("files", {})
    except Exception as e:
        return False, [f"Corrupted FIM baseline file: {e}"]

    findings: List[str] = []

    for rel_path, expected_hash in baseline_files.items():
        full_path = base / rel_path
        if not full_path.exists():
            findings.append(f"MISSING: Monitored file '{rel_path}' does not exist on disk.")
            continue

        actual_hash = compute_file_sha256(full_path)
        if actual_hash != expected_hash:
            findings.append(
                f"TAMPERED: Monitored file '{rel_path}' hash mismatch! "
                f"Expected: {expected_hash[:12]}... Actual: {actual_hash[:12]}..."
            )

    is_intact = len(findings) == 0

    if db_path:
        from audit.logger import AuditLogger
        from audit.models import AuditResult, EventType

        audit = AuditLogger(db_path=db_path)
        if is_intact:
            audit.log(
                event_type=EventType.SYSTEM.value,
                identity="system.fim",
                action="FIM_INTEGRITY_VERIFIED",
                result=AuditResult.SUCCESS.value,
                detail=f"Verified {len(baseline_files)} system critical files. All hashes match.",
            )
        else:
            audit.log(
                event_type=EventType.SYSTEM.value,
                identity="system.fim",
                action="FIM_TAMPERING_ALERT",
                result=AuditResult.FAILURE.value,
                detail=f"Detected {len(findings)} integrity violations: {'; '.join(findings)}",
            )

    return is_intact, findings
