# CampusVault — STRIDE Threat Model Worksheet & Security Analysis

**Assessment:** Practical Assessment 9 — STRIDE Threat Modeling & Secure Implementation  
**Project:** CampusVault Academic Security Portal  
**Target Environment:** Local Windows 11 / Python 3.14  
**Date:** September 2026  

---

## 1. System Architecture & Trust Boundaries

CampusVault enforces four distinct trust zones separated by explicit cryptographic and policy barriers:

```
[ UNTRUSTED ZONE: Public Clients / Simulated Sensors / Network Attackers ]
          │                                          │
          │ HTTPS (TLS 1.3 / AES-GCM)                │ mTLS (Client Auth) + HMAC-SHA256
          ▼                                          ▼
┌──────────────────────────────────────┐   ┌──────────────────────────────────────┐
│       CampusVault Web Portal         │   │         Sensor Telemetry API         │
│          (Port :8443)                │   │             (Port :8444)             │
└──────────────────────────────────────┘   └──────────────────────────────────────┘
          │                                          │
══════════╪══════════════════════════════════════════╪══════════════════════════════
 TRUST BOUNDARY: SERVER-SIDE RBAC & INTEGRITY GATEWAY (Deny-by-Default)
══════════╪══════════════════════════════════════════╪══════════════════════════════
          ▼                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           TRUSTED APPLICATION CORE                              │
│  - Session Engine (32-byte cryptographically random tokens)                     │
│  - RBAC Middleware (require_role, require_permission, check_ownership)          │
│  - Envelope Encryption Engine (AES-256-GCM DEK generation & wrapping)           │
│  - Digital Signature Engine (Ed25519 SHA-256 detached verification)             │
│  - Replay Defense Cache (in-memory + persistent SQLite nonce cache)             │
│  - Sliding Window Rate Limiter (10 req/min per IP)                             │
└─────────────────────────────────────────────────────────────────────────────────┘
          │
══════════╪════════════════════════════════════════════════════════════════════════
 TRUST BOUNDARY: ISOLATED KEY VAULT & AUDIT SUBSYSTEM
══════════╪════════════════════════════════════════════════════════════════════════
          ▼
┌──────────────────────────────────────┐   ┌──────────────────────────────────────┐
│      Key Management Service          │   │      Hash-Chained Audit Ledger       │
│  - Wrapped at rest by CV_MASTER_KEY  │   │  - Genesis block: 64 zeros           │
│  - Lifecycle: Active/Retired/Revoked │   │  - SHA-256 continuous hash chain     │
│  - Automated audit integration       │   │  - Zero secrets in detail logs       │
└──────────────────────────────────────┘   └──────────────────────────────────────┘
```

---

## 2. STRIDE Threat Model Worksheet

| Threat ID | STRIDE Category | Target Component | Threat Description | Likelihood | Impact | Implemented Control | Enforcing Code Module | Verifying Test Case |
|---|---|---|---|---|---|---|---|---|
| **T1** | **Spoofing** | Portal Authentication (`/login`) | Attacker guesses student or faculty credentials via credential stuffing or dictionary attacks. | High | High | Argon2id password hashing, per-user salts, 12+ character complexity check, password blocklist, and automatic 5-attempt account lockout (15-min window). | `app/auth.py`<br>`app/session.py` | `tests/test_01_password.py`<br>`tests/test_09_stride.py::test_stride_spoofing_prevented` |
| **T2** | **Tampering** | Sensor Telemetry (`/api/v1/telemetry`) | Man-in-the-middle attacker intercepts and alters environmental readings (temperature/humidity). | Medium | High | Canonical request HMAC-SHA256 signature verification over Method, Path, Timestamp, Nonce, and SHA-256(Body). Rejection of any modified payload. | `api/hmac_auth.py` | `tests/test_06_hmac_api.py`<br>`tests/test_09_stride.py::test_stride_tampering_prevented` |
| **T3** | **Repudiation** | Document & Grade Records | Faculty member uploads an incorrect or malicious syllabus and later denies having issued it. | Low | High | Cryptographic Ed25519 digital signatures computed over SHA-256 content hashes, saved as detached `.sig` files, and non-repudiable audit logging. | `app/signatures.py`<br>`audit/logger.py` | `tests/test_03_signatures.py`<br>`tests/test_07_audit_log.py` |
| **T4** | **Information Disclosure** | Data Storage (`data/files/`, `data/*.db`) | Unauthorized operator or attacker accesses files on disk to inspect confidential transcripts. | Medium | Critical | AES-256-GCM envelope encryption at rest. Every file is encrypted with a unique random DEK wrapped under KeyService KEK. Key material is wrapped by master key. | `app/encryption.py`<br>`keyservice/store.py` | `tests/test_02_encryption.py`<br>`tests/test_08_key_mgmt.py` |
| **T5** | **Denial of Service** | Telemetry Ingestion Endpoint | Attacker floods telemetry API with rapid bursts of requests to exhaust system resources. | High | Medium | Sliding window rate limiting (10 requests/minute per client IP) returning HTTP 429 Too Many Requests with standard `Retry-After` header. | `api/rate_limiter.py` | `tests/test_06_hmac_api.py`<br>`tests/test_09_stride.py::test_stride_denial_of_service_mitigated` |
| **T6** | **Elevation of Privilege** | Student & Admin Routes | Authenticated student crafts direct requests to administrative endpoints (`/admin/dashboard`) or queries another student's marks. | High | High | Server-side RBAC dependencies (`require_role`), deny-by-default role-permission matrix, and strict ownership checks (`check_ownership`). | `app/rbac.py`<br>`app/routes_admin.py`<br>`app/routes_student.py` | `tests/test_05_rbac.py`<br>`tests/test_09_stride.py::test_stride_elevation_of_privilege_blocked` |
| **T7** | **Tampering** | Audit Log Table | Attacker alters or deletes audit log entries to cover tracks of an unauthorized administrative action. | Low | Critical | Append-only hash chain linking each record's SHA-256 to the previous record's hash. The verifier utility (`verify_audit`) immediately detects modified or broken links. | `audit/logger.py`<br>`audit/verifier.py` | `tests/test_07_audit_log.py`<br>`tests/test_09_stride.py::test_stride_tampering_detected_in_audit_chain` |

---

## 3. Threat-Control-Test Traceability Matrix

```
┌─────────────┐        ┌─────────────────────────┐        ┌────────────────────────────┐
│   THREAT    │ ───►   │    SECURITY CONTROL     │ ───►   │   AUTOMATED PYTEST TEST    │
├─────────────┼────────┼─────────────────────────┼────────┼────────────────────────────┤
│ T1 Spoofing │        │ Argon2id + Lockout      │        │ test_01_password.py        │
│ T2 Tamper   │        │ Canonical HMAC-SHA256   │        │ test_06_hmac_api.py        │
│ T3 Repudiate│        │ Ed25519 Signatures      │        │ test_03_signatures.py      │
│ T4 InfoDisc │        │ AES-256-GCM Envelope    │        │ test_02_encryption.py      │
│ T5 DoS      │        │ Sliding Rate Limiter    │        │ test_06_hmac_api.py        │
│ T6 PrivEsc  │        │ Server RBAC + Ownership │        │ test_05_rbac.py            │
│ T7 Tamper   │        │ Hash-Chained Audit Log  │        │ test_07_audit_log.py       │
└─────────────┘        └─────────────────────────┘        └────────────────────────────┘
```

---

## 4. Before & After Security Demonstrations

### Scenario A: Elevation of Privilege Protection (T6)
- **Before Control (Vulnerable Baseline):** Direct HTTP request to `/admin/dashboard` with a student cookie would return administrative data, exposing key management and audit logs.
- **After Control (CampusVault):** The `require_role("admin")` dependency inspects the authenticated session, identifies the student role, logs an `ACCESS_DENIED` security incident to the hash-chained audit ledger, and returns HTTP 403 Forbidden.

### Scenario B: Telemetry Payload Tampering (T2)
- **Before Control (Vulnerable Baseline):** Plain JSON POST requests could be intercepted and altered (e.g. changing 21.5°C to 99.9°C) with no detection.
- **After Control (CampusVault):** The API reconstructs the canonical request string and calculates `HMAC-SHA256(canonical_data, shared_secret)`. Modifying even a single character in the body causes signature mismatch, returning HTTP 401 Unauthorized and alerting administrators.

### Scenario C: Audit Record Alteration (T7)
- **Before Control (Vulnerable Baseline):** Standard database rows can be updated via SQL without detection.
- **After Control (CampusVault):** Each entry includes `prev_hash` and `record_hash = SHA256(canonical_fields)`. Running `python scripts/verify_audit.py` instantly flags the exact record ID where the chain was broken or modified.
