# CampusVault — Assessment Implementation Notes

This document provides detailed implementation and defense notes for all 10 assessments in the HCLTech Cybersecurity Practical Assessments curriculum.

---

### Assessment 1: Secure Password Storage
- **Objective:** Securely store and verify credentials, enforce strict complexity policies, prevent password reuse, and protect against brute-force attacks.
- **Implementation:**
  - Hasher: `argon2-cffi` Argon2id with memory-hard parameters (`time_cost=3`, `memory_cost=65536`, `parallelism=4`).
  - Policy enforcement: `check_password_policy()` requiring >=12 characters, uppercase, lowercase, digit, special character, and rejection of top common passwords.
  - History tracking: `password_history` table stores prior hashes; `change_password()` validates against the last 3 passwords.
  - Account lockout: `login_user()` locks account for 15 minutes after 5 consecutive failures.
  - Single-use recovery: `initiate_recovery()` generates a 256-bit token; `complete_recovery()` verifies Argon2id hash within 1 hour.
- **Security Decisions:** Dummy hash verification prevents timing-based user enumeration. Passwords never appear in logs.
- **Test File:** `tests/test_01_password.py` (5 tests passing).
- **Evidence:** `evidence/assessment_01/db_extract_users_masked.txt`, `evidence/assessment_01/test_output.txt`.

---

### Assessment 2: Authenticated File Encryption
- **Objective:** Protect stored documents with authenticated encryption ensuring confidentiality and integrity.
- **Implementation:**
  - Web Portal: Envelope encryption via `encrypt_file_data()` and `decrypt_file_data()`. Generates per-file 256-bit DEK, encrypts with AES-256-GCM using 12-byte random nonces, and wraps DEK under KeyService KEK.
  - Standalone CLI: `vault/vaultctl.py` provides `encrypt`, `decrypt`, and `inspect` using `scrypt` (N=32768, r=8, p=1) and AES-256-GCM.
- **Security Decisions:** Never reuse nonces (`os.urandom(12)`). Cryptographic authentication tag verification prevents ciphertext tampering; any flipped bit raises `IntegrityError`.
- **Test File:** `tests/test_02_encryption.py` (5 tests passing).
- **Evidence:** `evidence/assessment_02/vaultctl_demo.txt`, `evidence/assessment_02/test_output.txt`.

---

### Assessment 3: Digital Signatures
- **Objective:** Provide non-repudiation and verify document authenticity before student access.
- **Implementation:**
  - Module: `app/signatures.py`.
  - Primitive: Ed25519 asymmetric signatures over SHA-256 content hashes.
  - Storage: Stored as detached `.sig` JSON files alongside encrypted archives.
  - Portal Download Gate: `download_document()` decrypts plaintext, loads `.sig`, and verifies Ed25519 signature before streaming to client.
- **Security Decisions:** Even if an encryption key or database is accessed, an attacker cannot forge signatures without the Ed25519 private key. Retired keys remain capable of signature verification to preserve historical records.
- **Test File:** `tests/test_03_signatures.py` (5 tests passing).
- **Evidence:** `evidence/assessment_03/sample_sig.json`, `evidence/assessment_03/test_output.txt`.

---

### Assessment 4: Public Key Infrastructure & Mutual TLS
- **Objective:** Establish a private PKI hierarchy and secure communication channels using server TLS and client certificate authentication.
- **Implementation:**
  - Script: `pki/generate_pki.py`.
  - Artifacts:
    - Root CA: Self-signed RSA-2048, 10-year validity, `CA:TRUE`, `keyCertSign`.
    - Server Certificate: Signed by CA, SAN with `localhost` & `127.0.0.1`, `serverAuth`.
    - Client Certificate: Signed by CA, `clientAuth` for sensor nodes.
  - Portal Server: HTTPS on port 8443.
  - Sensor Server: mTLS on port 8444.
- **Security Decisions:** Hostname validation and validity dates are enforced. Private keys are separated in `pki/private/` and excluded from git.
- **Test File:** `tests/test_04_pki_mtls.py` (5 tests passing).
- **Evidence:** `evidence/assessment_04/cert_inspection.txt`, `evidence/assessment_04/test_output.txt`.

---

### Assessment 5: Role-Based Access Control
- **Objective:** Enforce principle of least privilege, deny-by-default access, and prevent horizontal/vertical privilege escalation.
- **Implementation:**
  - Module: `app/rbac.py`.
  - Roles: `student`, `faculty`, `admin` defined in `roles` table with permission arrays.
  - Ownership Enforcement: Students can only view marks where `student_id == user["user_id"]`.
  - Session Security: 32-byte cryptographically random session tokens, 30-minute expiration, and explicit invalidation on logout.
- **Security Decisions:** Server-side validation on every endpoint. Unauthorized access attempts log `ACCESS_DENIED` to audit and return HTTP 403.
- **Test File:** `tests/test_05_rbac.py` (5 tests passing).
- **Evidence:** `evidence/assessment_05/roles_and_permissions.txt`, `evidence/assessment_05/test_output.txt`.

---

### Assessment 6: Secure API with HMAC
- **Objective:** Authenticate API requests, prevent message tampering, block replay attacks, and prevent denial-of-service flooding.
- **Implementation:**
  - Modules: `api/hmac_auth.py`, `api/nonce_cache.py`, `api/rate_limiter.py`.
  - Canonical request format: `METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(BODY)\n`.
  - Verification: `hmac.compare_digest()` constant-time check.
  - Anti-Replay: Nonce cache (in-memory + SQLite table) rejects duplicate nonces.
  - Anti-Skew: Rejects timestamps older than 300 seconds.
  - Rate Limiting: Sliding window limiter restricts client IP to 10 req/min with HTTP 429 and `Retry-After`.
- **Test File:** `tests/test_06_hmac_api.py` (5 tests passing).
- **Evidence:** `evidence/assessment_06/sensor_protocol.txt`, `evidence/assessment_06/test_output.txt`.

---

### Assessment 7: Tamper-Evident Audit Logging
- **Objective:** Build an append-only, verifiable audit trail that detects unauthorized log alterations.
- **Implementation:**
  - Modules: `audit/logger.py`, `audit/verifier.py`, `scripts/verify_audit.py`.
  - Hash Chaining: Genesis block hash is 64 zeros. Every record includes `prev_hash` (the prior record's hash) and `record_hash` computed over canonical JSON fields using SHA-256.
  - Detail Scrubbing: Regex redaction replaces passwords, tokens, and keys with `[REDACTED]`.
  - Verifier: `verify_audit()` re-evaluates the entire chain from genesis, reporting exact records where tampering or link breaks occur.
- **Test File:** `tests/test_07_audit_log.py` (5 tests passing).
- **Evidence:** `evidence/assessment_07/audit_verify_output.txt`, `evidence/assessment_07/audit_records_sample.txt`.

---

### Assessment 8: Cryptographic Key Management
- **Objective:** Manage key lifecycle (generation, storage, rotation, revocation, destruction) securely.
- **Implementation:**
  - Modules: `keyservice/service.py`, `keyservice/store.py`, `keyservice/models.py`.
  - Storage at Rest: All raw key material is wrapped using AES-256-GCM under `CV_MASTER_KEY` before persistence in `crypto_keys`.
  - Key Lifecycle:
    - `rotate_key()`: Marks old key `retired`, links `replaced_by`, and generates new active key.
    - `revoke_key()`: Marks key `revoked`; subsequent unwrapping raises `KeyRevokedError`.
    - `destroy_key()`: Overwrites stored ciphertext with zeros and marks `destroyed`.
    - `backup()` / `restore()`: Exports and restores encrypted key records safely.
- **Test File:** `tests/test_08_key_mgmt.py` (5 tests passing).
- **Evidence:** `evidence/assessment_08/keys_metadata.txt`, `evidence/assessment_08/test_output.txt`.

---

### Assessment 9: STRIDE Secure Implementation
- **Objective:** Perform systematic threat modeling across trust boundaries and demonstrate working security controls.
- **Implementation:**
  - Documentation: `docs/STRIDE_WORKSHEET.md` analyzing 7 threats across all STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
  - Traceability: Every threat is mapped to an architectural control and an automated test case.
- **Test File:** `tests/test_09_stride.py` (6 tests passing).
- **Evidence:** `evidence/assessment_09/stride_traceability.txt`, `docs/STRIDE_WORKSHEET.md`.

---

### Assessment 10: Software Bill of Materials & Dependency Assessment
- **Objective:** Generate machine-readable SBOMs and perform dependency vulnerability auditing and remediation.
- **Implementation:**
  - Tooling: `cyclonedx-py` (CycloneDX JSON 1.5) and `pip-audit`.
  - Baseline Scan: Detected known security advisories in outdated dependency `Jinja2==3.1.2`.
  - Remediation: Upgraded dependency to `Jinja2==3.1.6`.
  - Verification: Regenerated `sbom/sbom_after.json` and verified with `pip-audit`, confirming 0 known vulnerabilities.
- **Test File:** `tests/test_10_sbom.py` (5 tests passing).
- **Evidence:** `sbom/sbom_before.json`, `sbom/audit_before.txt`, `sbom/sbom_after.json`, `sbom/audit_after.txt`, `sbom/DEPENDENCY_REPORT.md`.
