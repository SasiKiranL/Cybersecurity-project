"""CampusVault Audit Log Integrity Verifier CLI.

Performs cryptographic verification of the hash-chained audit log.
Walks the entire chain from genesis (64 zeros) through every entry,
validating SHA-256 links and data integrity.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.config import get_settings
from app.database import get_db_connection
from audit.verifier import verify_audit


def main() -> None:
    parser = argparse.ArgumentParser(description="CampusVault Audit Log Cryptographic Integrity Verifier")
    parser.add_argument("--db", help="Path to campusvault.db (defaults to configured DB)")
    args = parser.parse_args()

    settings = get_settings()
    db_path = Path(args.db) if args.db else settings.db_path

    if not db_path.exists():
        print(f"[-] Database not found at '{db_path}'.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Verifying audit log integrity in '{db_path}'...")
    conn = get_db_connection(db_path)
    count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    conn.close()
    print(f"[*] Found {count} total audit records in chain.")

    is_valid, errors = verify_audit(db_path)

    if is_valid:
        print("[+] VERIFICATION SUCCESS: All cryptographic hashes and chain links are valid!")
        print(f"[+] The audit log is completely tamper-free across all {count} records.")
        sys.exit(0)
    else:
        print("[-] VERIFICATION FAILURE: Tampering detected!", file=sys.stderr)
        for err in errors:
            print(f"    [!] {err}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
