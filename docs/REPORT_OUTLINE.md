# CampusVault — Final Project Report Outline

This outline provides the structural template for preparing the 3-5 page submission report for the HCLTech Cybersecurity Practical Assessment.

---

## 1. Executive Summary & Project Context (approx. 0.5 page)
- **1.1 Purpose:** CampusVault is a comprehensive security portal and IoT telemetry platform developed to fulfill all ten HCLTech practical cybersecurity assessments in a single cohesive system.
- **1.2 Key Objectives:**
  - Secure credential storage and identity management.
  - Authenticated file encryption and non-repudiable digital signatures.
  - Private PKI architecture and mutual TLS (mTLS).
  - Fine-grained role-based access control (RBAC) and least privilege.
  - Cryptographically signed API communication with replay defense.
  - Tamper-evident, hash-chained audit logging.
  - Centralized cryptographic key lifecycle management.
  - STRIDE threat modeling and CycloneDX SBOM supply chain analysis.
- **1.3 Compliance & Execution:** Fully operational on Windows 11 with Python, utilizing synthetic data only, with 100% automated test coverage (51 passing unit/integration tests).

---

## 2. System Architecture & Trust Boundaries (approx. 1 page)
- **2.1 Component Overview:**
  - Web Portal (`:8443`) for Students, Faculty, and Administrators.
  - IoT Telemetry API (`:8444`) for environmental laboratory sensors.
  - Key Management Service & Hash-Chained Audit Subsystems.
- **2.2 Trust Zones & Threat Boundaries:**
  - Untrusted Client Zone vs TLS/mTLS Edge vs Trusted Core vs Protected Vault.
- **2.3 Architecture Diagram:**
  - Reference to Section 1.3 Mermaid Architecture diagram.

---

## 3. Implementation of Core Security Controls (approx. 1.5 pages)
- **3.1 Identity & Access Governance (Assessments 1 & 5):**
  - Argon2id memory-hard password hashing with per-user salts.
  - 12+ character complexity enforcement and common password blocklist.
  - 5-attempt account lockout and last-3 password history prevention.
  - Server-side RBAC matrix (`student`, `faculty`, `admin`) with ownership checks.
- **3.2 Cryptographic Data Protection (Assessments 2, 3, & 8):**
  - AES-256-GCM envelope encryption with random DEKs wrapped under KeyService KEKs.
  - Standalone passphrase encryption via `vault/vaultctl.py` (scrypt KDF).
  - Ed25519 digital signatures with detached `.sig` files and mandatory download verification.
  - Centralized KeyService managing key generation, rotation, revocation, and AES-GCM encrypted storage at rest.
- **3.3 Secure Communications & Sensor Ingest (Assessments 4 & 6):**
  - Private PKI generating Root CA, server certs with SANs, and mTLS client certs.
  - Canonical request HMAC-SHA256 signature verification.
  - Anti-replay nonce cache and 300-second timestamp tolerance.
  - Sliding-window rate limiter (10 req/min) returning HTTP 429.
- **3.4 Tamper-Evident Accountability (Assessment 7):**
  - SHA-256 hash-chained audit ledger starting from genesis (64 zeros).
  - Automated redaction of sensitive credentials in log details.
  - Command-line and dashboard audit verification tool (`scripts/verify_audit.py`).

---

## 4. Threat Modeling & Supply Chain Security (approx. 1 page)
- **4.1 STRIDE Threat Analysis (Assessment 9):**
  - Analysis of 7 threats across all STRIDE categories.
  - Threat-Control-Test traceability matrix.
  - Before/after defense demonstrations.
- **4.2 Software Bill of Materials & Vulnerability Remediation (Assessment 10):**
  - CycloneDX JSON 1.5 SBOM generation (`sbom/sbom_before.json`, `sbom/sbom_after.json`).
  - Automated `pip-audit` identifying vulnerable dependency (`Jinja2==3.1.2`).
  - Upgrade to `Jinja2==3.1.6` achieving zero remaining vulnerabilities.

---

## 5. Verification Results & Metrics (approx. 0.5 page)
- **5.1 Test Suite Summary:**
  - 51 tests across 10 test modules: **100% pass rate**.
  - Execution time: ~5.6 seconds.
- **5.2 Integrity & Assurance Checklist:**
  - Clean audit verification over all database events.
  - Full cryptographic separation of keys.
  - Zero hard-coded credentials or exposed secrets.

---

## 6. Appendices
- **Appendix A:** Repository Structure & File Catalog.
- **Appendix B:** Complete Test Execution Log.
- **Appendix C:** Evidence Artifacts & Screenshot Guide.
