"""Command-line runner for CampusVault Cryptographic File Integrity Monitor (FIM).

Usage:
    python scripts/run_fim.py --init     # Generate initial cryptographic baseline
    python scripts/run_fim.py --check    # Verify current file hashes against baseline
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from audit.fim import generate_fim_baseline, verify_fim


def main():
    parser = argparse.ArgumentParser(description="CampusVault File Integrity Monitor")
    parser.add_argument("--init", action="store_true", help="Generate or refresh baseline hashes")
    parser.add_argument("--check", action="store_true", help="Verify integrity against baseline")
    args = parser.parse_args()

    baseline_path = BASE_DIR / "data" / "fim_baseline.json"
    db_path = BASE_DIR / "data" / "campusvault.db"

    if args.init:
        print("[*] Generating SHA-256 FIM cryptographic baseline...")
        hashes = generate_fim_baseline(BASE_DIR, baseline_path)
        print(f"[+] Baseline successfully written to {baseline_path} ({len(hashes)} files tracked):")
        for f, h in hashes.items():
            print(f"    - {f}: {h[:16]}...")
        return

    # Default to check
    print(f"[*] Checking file integrity against {baseline_path}...")
    is_intact, findings = verify_fim(BASE_DIR, baseline_path, db_path if db_path.exists() else None)
    if is_intact:
        print("[+] SUCCESS: All monitored configuration and code files match cryptographic baseline.")
    else:
        print(f"[-] TAMPERING DETECTED: {len(findings)} violation(s) found:")
        for finding in findings:
            print(f"    ! {finding}")
        sys.exit(1)


if __name__ == "__main__":
    main()
