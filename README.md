# CampusVault — Enterprise Cybersecurity Student Project

**CampusVault** is a unified, production-grade cybersecurity reference application developed for the HCLTech Cybersecurity Practical Assessments. It integrates all ten practical curriculum assessments into a single cohesive system featuring a secure academic web portal, an IoT telemetry API, a cryptographic key management service, and an append-only hash-chained audit ledger.

Everything runs locally on Windows 11 with Python and PowerShell. No cloud services or Docker containers are required.

---

## 🛡️ Assessment Coverage Matrix

| Assessment | Title | Implemented Modules | Test Suite | Evidence Artifacts |
|---|---|---|---|---|
| **Assessment 1** | Secure Password Storage | `app/auth.py` | `tests/test_01_password.py` | `evidence/assessment_01/` |
| **Assessment 2** | Authenticated File Encryption | `app/encryption.py`, `vault/vaultctl.py` | `tests/test_02_encryption.py` | `evidence/assessment_02/` |
| **Assessment 3** | Digital Signatures | `app/signatures.py` | `tests/test_03_signatures.py` | `evidence/assessment_03/` |
| **Assessment 4** | PKI and Mutual TLS | `pki/generate_pki.py` | `tests/test_04_pki_mtls.py` | `evidence/assessment_04/` |
| **Assessment 5** | Role-Based Access Control | `app/rbac.py`, `app/session.py` | `tests/test_05_rbac.py` | `evidence/assessment_05/` |
| **Assessment 6** | Secure API with HMAC | `api/hmac_auth.py`, `api/nonce_cache.py`, `api/rate_limiter.py` | `tests/test_06_hmac_api.py` | `evidence/assessment_06/` |
| **Assessment 7** | Tamper-Evident Audit Logging | `audit/logger.py`, `audit/verifier.py` | `tests/test_07_audit_log.py` | `evidence/assessment_07/` |
| **Assessment 8** | Cryptographic Key Management | `keyservice/service.py`, `keyservice/store.py` | `tests/test_08_key_mgmt.py` | `evidence/assessment_08/` |
| **Assessment 9** | STRIDE Threat Modeling | `docs/STRIDE_WORKSHEET.md` | `tests/test_09_stride.py` | `evidence/assessment_09/` |
| **Assessment 10** | SBOM & Dependency Assessment | `sbom/` | `tests/test_10_sbom.py` | `sbom/`, `evidence/assessment_10/` |

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Operating System:** Windows 11
- **Shell:** PowerShell
- **Python:** Python 3.12+ (or Python 3.14)
- **Virtual Environment:** `.venv`

### 2. Environment Activation & Dependencies
Activate the virtual environment:
```powershell
.\.venv\Scripts\Activate.ps1
```
Dependencies are already pinned in `requirements.txt`. If installing freshly:
```powershell
pip install -r requirements.txt
```

### 3. Generate PKI Certificates (Assessment 4)
Generate the local Root CA, Server TLS certificate, and Client mTLS certificate:
```powershell
python pki/generate_pki.py
```
*(Creates `pki/ca.crt`, `pki/server.crt`, `pki/client.crt`, and private keys in `pki/private/`)*

### 4. Seed Synthetic Data (Assessments 1, 2, 3, 5, 8)
Initialize the SQLite database, seed master cryptographic keys, synthetic users, academic marks, and a sample signed/encrypted course syllabus:
```powershell
python scripts/seed_data.py
```

### 5. Run the Automated Test Suite (All 10 Assessments)
Run all 51 test cases across the entire project:
```powershell
pytest -v
```
*(Expected: **51 passed** in ~5 seconds)*

---

## 🌐 Running the Servers

CampusVault operates two distinct servers running on separate ports:

### 1. Web Portal (HTTPS on `:8443`)
Launch the user-facing web portal:
```powershell
python scripts/run_portal.py
```
Open your browser and navigate to:
```
https://localhost:8443
```
*(Accept the self-signed certificate warning in your browser for local testing)*

#### Demo Accounts (Synthetic Data)
| Role | Username | Password | Purpose |
|---|---|---|---|
| **Student** | `alice_student` | `StudentPass123!Safe` | View marks (ownership protected) & download verified syllabus |
| **Faculty** | `bob_faculty` | `FacultyPass123!Safe` | Enter course marks & upload/sign/envelope-encrypt documents |
| **Admin** | `carol_admin` | `AdminPass123!Safe` | Audit log viewer, run cryptographic chain verification, key rotation |

### 2. Sensor Telemetry API (mTLS on `:8444`)
Launch the mutual TLS IoT telemetry ingest server in a separate terminal:
```powershell
python scripts/run_api.py
```

### 3. Run Simulated Sensor Client (mTLS + HMAC-SHA256)
Run the simulated sensor node to transmit signed telemetry readings:
```powershell
python simulator/sensor_client.py --iterations 3
```

---

## 🧰 Standalone Utilities

### 1. VaultCTL CLI (Assessment 2)
CampusVault provides a standalone authenticated encryption tool using scrypt and AES-256-GCM:

**Encrypt a file:**
```powershell
python -m vault.vaultctl encrypt -i requirements.txt -o vault_secret.enc -p "SecurePassphrase123!"
```

**Inspect file header without decrypting:**
```powershell
python -m vault.vaultctl inspect -i vault_secret.enc
```

**Decrypt the file:**
```powershell
python -m vault.vaultctl decrypt -i vault_secret.enc -o requirements_restored.txt -p "SecurePassphrase123!"
```

### 2. Audit Log Integrity Verifier (Assessment 7)
Verify that the audit ledger has not been tampered with:
```powershell
python scripts/verify_audit.py
```
*(Walks the SHA-256 hash chain from genesis to verify link continuity)*

### 3. Software Supply Chain Auditing (Assessment 10)
Generate an authoritative CycloneDX SBOM:
```powershell
python -m cyclonedx_py requirements requirements.txt -o sbom/sbom_after.json --of JSON
```
Execute vulnerability scanning with `pip-audit`:
```powershell
pip-audit -r requirements.txt
```

---

## 📁 Repository Structure

```
CampusVault/
├── .env                       # Environment configuration (secrets, ports, paths)
├── .gitignore                  # Git ignore rules (secrets, private keys, databases)
├── requirements.txt            # Pinned dependency manifest
├── README.md                   # System documentation and quick start
│
├── api/                        # Assessment 6: Sensor Telemetry API
│   ├── hmac_auth.py            # Canonical request HMAC-SHA256 verification
│   ├── nonce_cache.py          # Anti-replay nonce cache with SQLite persistence
│   ├── rate_limiter.py         # Sliding window rate limiter (10 req/min)
│   └── main.py                 # FastAPI sensor application
│
├── app/                        # Web Portal Application
│   ├── auth.py                 # Assessment 1: Argon2id password hashing, lockout, recovery
│   ├── config.py               # Pydantic settings & secret loading
│   ├── database.py             # SQLite WAL database & schema manager
│   ├── encryption.py           # Assessment 2: Envelope encryption (AES-256-GCM)
│   ├── models.py               # Schemas & data structures
│   ├── rbac.py                 # Assessment 5: Role-based access control dependencies
│   ├── routes_admin.py         # Admin panel & key rotation routes
│   ├── routes_auth.py          # Login, registration, password recovery routes
│   ├── routes_faculty.py       # Grade entry & document signing routes
│   ├── routes_student.py       # Grade viewer & signature-verified download routes
│   ├── session.py              # Cryptographic session & CSRF management
│   ├── signatures.py           # Assessment 3: Ed25519 digital signatures
│   ├── main.py                 # Portal application assembly & security headers
│   └── templates/              # Modern glassmorphism HTML templates
│
├── audit/                      # Assessment 7: Tamper-Evident Audit Logging
│   ├── logger.py               # Thread-safe hash-chained audit logger with scrubbing
│   ├── models.py               # AuditEvent, EventType, genesis hash
│   └── verifier.py             # Full chain integrity verifier
│
├── data/                       # Local data storage (Git ignored)
│   ├── campusvault.db          # Main SQLite database
│   └── files/                  # Encrypted archives (.enc) & detached signatures (.sig)
│
├── docs/                       # Project Documentation
│   ├── ARCHITECTURE.md         # Detailed technical architecture & sequence flows
│   ├── ASSESSMENT_NOTES.md     # In-depth notes for all 10 assessments
│   ├── IMPLEMENTATION_PLAN.md  # Comprehensive architectural blueprint
│   ├── REPORT_OUTLINE.md       # Outline for 3-5 page submission report
│   └── STRIDE_WORKSHEET.md     # Assessment 9: Full STRIDE threat model & matrix
│
├── evidence/                   # Assessment Demonstration Evidence
│   ├── assessment_01/ to assessment_10/ # Test outputs, database extracts, logs
│
├── keyservice/                 # Assessment 8: Cryptographic Key Management
│   ├── models.py               # Key states (active, retired, revoked, destroyed)
│   ├── service.py              # Key lifecycle (generate, rotate, revoke, backup)
│   └── store.py                # Master key wrapping using AES-256-GCM at rest
│
├── pki/                        # Assessment 4: Private PKI & TLS
│   ├── generate_pki.py         # Root CA, Server cert, and Client mTLS cert generator
│   └── private/                # Private keys (restricted permissions, Git ignored)
│
├── sbom/                       # Assessment 10: Supply Chain & SBOM
│   ├── sbom_before.json        # Pre-remediation CycloneDX SBOM
│   ├── audit_before.txt        # Pre-remediation pip-audit report (vulnerability found)
│   ├── sbom_after.json         # Post-remediation CycloneDX SBOM
│   ├── audit_after.txt         # Post-remediation pip-audit report (0 vulnerabilities)
│   └── DEPENDENCY_REPORT.md    # Detailed supply chain analysis
│
├── scripts/                    # Management & Verification Scripts
│   ├── generate_evidence.py    # Generates all evidence folder artifacts
│   ├── run_api.py              # Runs Sensor API on :8444 with mTLS
│   ├── run_portal.py           # Runs Web Portal on :8443 with TLS
│   ├── seed_data.py            # Seeds database with synthetic users and keys
│   └── verify_audit.py         # CLI audit chain verifier
│
├── simulator/                  # Simulated IoT Sensor Node
│   └── sensor_client.py        # Telemetry transmitter using mTLS + HMAC-SHA256
│
├── tests/                      # Automated Pytest Suite (51 Tests)
│   ├── conftest.py             # Shared fixtures (temp DB, key service, audit logger)
│   ├── test_01_password.py     # Assessment 1 tests (5/5)
│   ├── test_02_encryption.py   # Assessment 2 tests (5/5)
│   ├── test_03_signatures.py   # Assessment 3 tests (5/5)
│   ├── test_04_pki_mtls.py     # Assessment 4 tests (5/5)
│   ├── test_05_rbac.py         # Assessment 5 tests (5/5)
│   ├── test_06_hmac_api.py     # Assessment 6 tests (5/5)
│   ├── test_07_audit_log.py    # Assessment 7 tests (5/5)
│   ├── test_08_key_mgmt.py     # Assessment 8 tests (5/5)
│   ├── test_09_stride.py       # Assessment 9 tests (6/6)
│   └── test_10_sbom.py         # Assessment 10 tests (5/5)
│
└── vault/                      # Standalone VaultCTL CLI Tool
    └── vaultctl.py             # scrypt + AES-GCM file encryption utility
```

---

## 🔒 Security Operational Notes

1. **Windows File Permissions (`icacls`):**
   Restrict the private keys directory to your Windows user account only:
   ```powershell
   icacls pki\private /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F"
   icacls .env /inheritance:r /grant:r "$($env:USERNAME):F"
   ```

2. **Zero Secrets in Code:**
   All secrets (`CV_MASTER_KEY`, `CV_HMAC_SECRET`, `CV_SESSION_SECRET`) are loaded from `.env` or system environment variables. The `.env` file is excluded in `.gitignore`.

3. **Safe Error Handling:**
   User-facing endpoints return generic messages (e.g. `"Authentication failed"` or `"Decryption failed"`). Cryptographic stack traces and detailed error context are recorded exclusively in the protected audit log.
