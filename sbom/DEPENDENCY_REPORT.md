# CampusVault — Software Bill of Materials (SBOM) & Dependency Security Assessment

**Assessment:** Practical Assessment 10 — Software Bill of Materials & Vulnerability Remediation  
**Target Standard:** CycloneDX JSON 1.5  
**Audit Tool:** `pip-audit`  
**Date:** September 2026  

---

## 1. Executive Summary

CampusVault utilizes an automated software supply chain security framework. In this assessment:
1. An initial Software Bill of Materials (SBOM) was generated in CycloneDX standard format.
2. A vulnerability scan was executed against the dependency baseline, identifying known CVEs in an outdated dependency (`Jinja2==3.1.2`).
3. The vulnerability was analyzed and remediated by upgrading the package to `Jinja2==3.1.6`.
4. A clean post-remediation SBOM was generated, and re-audit confirmed **0 known vulnerabilities**.

---

## 2. Pre-Remediation Vulnerability Scan

**Command executed:**
```powershell
pip-audit -r sbom/requirements_before.txt -o sbom/audit_before.txt -f columns
```

**Output summary (`sbom/audit_before.txt`):**
```
Name   Version ID              Fix Versions
------ ------- --------------- ------------
jinja2 3.1.2   PYSEC-2026-1473 3.1.3
jinja2 3.1.2   PYSEC-2026-1474 3.1.4
jinja2 3.1.2   PYSEC-2026-1475 3.1.5
jinja2 3.1.2   PYSEC-2026-1472 3.1.5
jinja2 3.1.2   PYSEC-2026-1471 3.1.6
```

### Vulnerability Analysis
- **Package:** `Jinja2` (Template rendering engine used by FastAPI)
- **Vulnerable Version:** `3.1.2`
- **Root Cause:** Multiple advisory entries related to compiler sandbox escaping and cross-site scripting (XSS) via attribute injection.
- **Severity Assessment:** High impact in applications allowing untrusted template evaluation; mitigated in CampusVault through template sanitization, but requires prompt supply chain remediation.

---

## 3. Remediation Action

1. Upgraded `Jinja2` from `3.1.2` to the secure pinned version `3.1.6` in `requirements.txt`.
2. Regenerated the authoritative CycloneDX SBOM:
   ```powershell
   python -m cyclonedx_py requirements requirements.txt -o sbom/sbom_after.json --of JSON
   ```
3. Re-ran full dependency security audit:
   ```powershell
   pip-audit -r requirements.txt -o sbom/audit_after.txt
   ```

---

## 4. Post-Remediation Verification

**Output (`sbom/audit_after.txt`):**
```
No known vulnerabilities found
```

### SBOM Component Verification
The post-remediation SBOM (`sbom/sbom_after.json`) contains:
- Total components tracked: 84
- Format: CycloneDX JSON schema
- Cryptographic hash references and Package URLs (PURLs) for all dependencies
- Pinned secure version: `pkg:pypi/jinja2@3.1.6`
- Zero unresolved security advisories
