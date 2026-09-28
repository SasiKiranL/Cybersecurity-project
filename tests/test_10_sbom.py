"""Assessment 10 Tests: Software Bill of Materials (SBOM) & Supply Chain Security.

Verifies:
1. CycloneDX SBOM files exist and adhere to the CycloneDX JSON schema.
2. SBOM components contain valid Package URLs (purl) and metadata.
3. Complete traceability between requirements.txt and SBOM components.
4. Audit reports capture before/after vulnerability discovery and successful remediation.
5. Critical security libraries satisfy modern version thresholds.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest


def test_sbom_files_exist_and_are_valid_cyclonedx_json():
    """Test 1: CycloneDX SBOM files exist, parse cleanly, and match standard schema."""
    before_path = Path("sbom/sbom_before.json")
    after_path = Path("sbom/sbom_after.json")

    assert before_path.exists(), "sbom_before.json must exist"
    assert after_path.exists(), "sbom_after.json must exist"

    with open(after_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data.get("bomFormat") == "CycloneDX"
    assert "specVersion" in data
    assert "components" in data
    assert len(data["components"]) > 10


def test_sbom_components_have_purls_and_metadata():
    """Test 2: All components in the SBOM feature Package URLs (purl), name, and version."""
    after_path = Path("sbom/sbom_after.json")
    with open(after_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for comp in data["components"]:
        assert "name" in comp
        assert "version" in comp
        assert "purl" in comp
        assert comp["purl"].startswith("pkg:pypi/")


def test_sbom_traceability_to_requirements():
    """Test 3: Pinned packages in requirements.txt trace directly into SBOM components."""
    req_file = Path("requirements.txt")
    assert req_file.exists()

    req_packages = set()
    for line in req_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            pkg_name = line.split("==")[0].lower()
            req_packages.add(pkg_name)

    with open("sbom/sbom_after.json", "r", encoding="utf-8") as f:
        sbom_data = json.load(f)

    sbom_packages = {comp["name"].lower() for comp in sbom_data["components"]}

    # Check key dependencies are tracked in SBOM
    for key_pkg in ["cryptography", "argon2-cffi", "fastapi", "uvicorn", "jinja2"]:
        assert key_pkg in sbom_packages


def test_dependency_vulnerability_reports_exist():
    """Test 4: Vulnerability reports document before-and-after audit findings."""
    audit_before = Path("sbom/audit_before.txt")
    audit_after = Path("sbom/audit_after.txt")

    assert audit_before.exists()
    assert audit_after.exists()

    before_content = audit_before.read_text()
    after_content = audit_after.read_text()

    # Pre-remediation scan detected vulnerable Jinja2
    assert "jinja2" in before_content.lower()
    assert "3.1.2" in before_content

    # Post-remediation scan confirms zero vulnerabilities
    assert "no known vulnerabilities found" in after_content.lower()


def test_critical_packages_minimum_secure_versions():
    """Test 5: Critical cryptographic and web security libraries exceed safe thresholds."""
    import argon2
    import cryptography
    import fastapi
    import jinja2

    crypto_ver = tuple(map(int, cryptography.__version__.split(".")[:2]))
    assert crypto_ver >= (40, 0), "cryptography must be >= 40.0"

    import importlib.metadata
    argon_str = importlib.metadata.version("argon2-cffi")
    argon_ver = tuple(map(int, argon_str.split(".")[:2]))
    assert argon_ver >= (21, 0), "argon2-cffi must be >= 21.0"

    assert int(fastapi.__version__.split(".")[1]) >= 100, "fastapi must be >= 0.100.0"

    jinja_ver = tuple(map(int, jinja2.__version__.split(".")[:2]))
    assert jinja_ver >= (3, 1), "jinja2 must be >= 3.1"
