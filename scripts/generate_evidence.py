"""Generate evidence artifacts and data extracts for all 10 assessments."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from cryptography import x509

conn = sqlite3.connect("data/campusvault.db")

# 1. Assessment 01: Masked user DB extract
cursor = conn.execute(
    "SELECT username, substr(password_hash, 1, 28) || '...' as masked_hash, role, failed_attempts FROM users"
)
rows = cursor.fetchall()
a1_text = "USERNAME        | MASKED_ARGON2ID_HASH            | ROLE    | FAILED_ATTEMPTS\n"
a1_text += "-" * 75 + "\n"
for u, h, r, f in rows:
    a1_text += f"{u:<15} | {h:<31} | {r:<7} | {f}\n"
Path("evidence/assessment_01/db_extract_users_masked.txt").write_text(a1_text)

# 2. Assessment 02: VaultCTL CLI run output
test_enc = Path("data/test_req.enc")
test_dec = Path("data/test_req.dec")
p_enc = subprocess.run(
    [sys.executable, "-m", "vault.vaultctl", "encrypt", "-i", "requirements.txt", "-o", str(test_enc), "-p", "DemoPassphrase123!"],
    capture_output=True, text=True
)
p_insp = subprocess.run(
    [sys.executable, "-m", "vault.vaultctl", "inspect", "-i", str(test_enc)],
    capture_output=True, text=True
)
p_dec = subprocess.run(
    [sys.executable, "-m", "vault.vaultctl", "decrypt", "-i", str(test_enc), "-o", str(test_dec), "-p", "DemoPassphrase123!"],
    capture_output=True, text=True
)
Path("evidence/assessment_02/vaultctl_demo.txt").write_text(p_enc.stdout + "\n" + p_insp.stdout + "\n" + p_dec.stdout)
if test_enc.exists():
    test_enc.unlink()
if test_dec.exists():
    test_dec.unlink()

# 3. Assessment 03: Detached signature sample
sig_files = list(Path("data/files").glob("*.sig"))
if sig_files:
    Path("evidence/assessment_03/sample_sig.json").write_text(sig_files[0].read_text())

# 4. Assessment 04: Certificate inspection
ca_cert = x509.load_pem_x509_certificate(Path("pki/ca.crt").read_bytes())
srv_cert = x509.load_pem_x509_certificate(Path("pki/server.crt").read_bytes())
cli_cert = x509.load_pem_x509_certificate(Path("pki/client.crt").read_bytes())
a4_text = f"""=== ROOT CA CERTIFICATE ===
Subject: {ca_cert.subject.rfc4514_string()}
Issuer: {ca_cert.issuer.rfc4514_string()}
Serial: {ca_cert.serial_number}
Not Before: {ca_cert.not_valid_before_utc}
Not After: {ca_cert.not_valid_after_utc}

=== SERVER CERTIFICATE ===
Subject: {srv_cert.subject.rfc4514_string()}
Issuer: {srv_cert.issuer.rfc4514_string()}
Not Before: {srv_cert.not_valid_before_utc}
Not After: {srv_cert.not_valid_after_utc}

=== CLIENT mTLS CERTIFICATE ===
Subject: {cli_cert.subject.rfc4514_string()}
Issuer: {cli_cert.issuer.rfc4514_string()}
Not Before: {cli_cert.not_valid_before_utc}
Not After: {cli_cert.not_valid_after_utc}
"""
Path("evidence/assessment_04/cert_inspection.txt").write_text(a4_text)

# 5. Assessment 05: Roles and Permissions Matrix
c_roles = conn.execute("SELECT name, permissions FROM roles").fetchall()
a5_text = "ROLE     | GRANTED PERMISSIONS\n" + "-" * 60 + "\n"
for r, p in c_roles:
    a5_text += f"{r:<8} | {p}\n"
Path("evidence/assessment_05/roles_and_permissions.txt").write_text(a5_text)

# 6. Assessment 06: Sensor protocol
Path("evidence/assessment_06/sensor_protocol.txt").write_text("""[PROTOCOL SPECIFICATION]
Method: POST
Path: /api/v1/telemetry
Headers:
  X-Timestamp: ISO 8601 UTC
  X-Nonce: UUIDv4
  X-Signature: HMAC-SHA256(Method + Path + Timestamp + Nonce + SHA256(Body), Secret)
Security Features:
  1. Anti-Replay: Nonce cache verification
  2. Anti-Skew: 300-second timestamp tolerance
  3. Anti-Tamper: Constant-time comparison (hmac.compare_digest)
  4. Rate-Limiting: Sliding window 10 req/min
""")

# 7. Assessment 07: Audit verification & sample
p_v = subprocess.run([sys.executable, "scripts/verify_audit.py"], capture_output=True, text=True)
Path("evidence/assessment_07/audit_verify_output.txt").write_text(p_v.stdout)
c_logs = conn.execute(
    "SELECT id, timestamp, identity, action, result, substr(record_hash, 1, 16) || '...' as hash FROM audit_log LIMIT 10"
).fetchall()
a7_text = "ID | TIMESTAMP           | IDENTITY        | ACTION                 | RESULT  | RECORD_HASH\n" + "-" * 85 + "\n"
for i, t, ident, act, res, h in c_logs:
    a7_text += f"{i:<2} | {t[:19]} | {ident:<15} | {act:<22} | {res:<7} | {h}\n"
Path("evidence/assessment_07/audit_records_sample.txt").write_text(a7_text)

# 8. Assessment 08: Keys metadata
c_keys = conn.execute("SELECT id, purpose, algorithm, state, created_at FROM crypto_keys").fetchall()
a8_text = "KEY_ID                               | PURPOSE    | ALGORITHM    | STATE   | CREATED_AT\n" + "-" * 85 + "\n"
for kid, p, algo, st, cr in c_keys:
    a8_text += f"{kid} | {p:<10} | {algo:<12} | {st:<7} | {cr[:19]}\n"
Path("evidence/assessment_08/keys_metadata.txt").write_text(a8_text)

# 9. Assessment 09: STRIDE traceability
Path("evidence/assessment_09/stride_traceability.txt").write_text("""[STRIDE THREAT-CONTROL-TEST TRACEABILITY MATRIX]
T1 (Spoofing):             Argon2id + Lockout      -> test_01_password.py, test_09_stride.py
T2 (Tampering):            Canonical HMAC-SHA256   -> test_06_hmac_api.py, test_09_stride.py
T3 (Repudiation):          Ed25519 Signatures      -> test_03_signatures.py, test_09_stride.py
T4 (Information Disclosure): AES-256-GCM Envelope  -> test_02_encryption.py, test_09_stride.py
T5 (Denial of Service):    Sliding Rate Limiter    -> test_06_hmac_api.py, test_09_stride.py
T6 (Elevation of Privilege): Server-side RBAC      -> test_05_rbac.py, test_09_stride.py
T7 (Tampering):            Hash-Chained Audit Log  -> test_07_audit_log.py, test_09_stride.py
""")

# 10. Assessment 10: Comparison
a10_text = """=== PRE-REMEDIATION AUDIT (audit_before.txt) ===
""" + Path("sbom/audit_before.txt").read_text() + """

=== POST-REMEDIATION AUDIT (audit_after.txt) ===
""" + Path("sbom/audit_after.txt").read_text()
Path("evidence/assessment_10/pip_audit_comparison.txt").write_text(a10_text)

conn.close()
print("All evidence successfully populated!")
