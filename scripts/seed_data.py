"""Synthetic seed data generator for CampusVault.

Seeds:
1. Key Service Master Keys (Encryption KEK, Ed25519 Signing, HMAC)
2. Roles and Permissions Matrix
3. Synthetic Users (Student Alice, Faculty Bob, Admin Carol)
4. Synthetic Course Marks for Students
5. Sample Encrypted and Digitally Signed Academic Documents
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.auth import register_user
from app.config import get_settings
from app.database import db_session, init_db
from app.encryption import encrypt_file_data
from app.signatures import save_detached_signature, sign_document
from keyservice.models import KeyAlgorithm, KeyPurpose
from keyservice.service import KeyService


def seed_all_data(db_path: Path | str | None = None) -> None:
    settings = get_settings()
    target_db = Path(db_path) if db_path else settings.db_path

    print(f"[*] Initializing database at '{target_db}'...")
    init_db(target_db)

    ks = KeyService(master_key=settings.get_master_key_bytes(), db_path=target_db)

    # 1. Generate core cryptographic keys
    print("[*] Generating Key Service master cryptographic keys...")
    try:
        enc_key_id = ks.get_active_key(KeyPurpose.ENCRYPTION).id
        print(f"    Existing encryption key: {enc_key_id}")
    except Exception:
        enc_key_id = ks.generate_key(KeyPurpose.ENCRYPTION, KeyAlgorithm.AES_256_GCM, created_by="system_setup")
        print(f"    Generated active encryption key: {enc_key_id}")

    try:
        sign_key_id = ks.get_active_key(KeyPurpose.SIGNING).id
        print(f"    Existing signing key: {sign_key_id}")
    except Exception:
        sign_key_id = ks.generate_key(KeyPurpose.SIGNING, KeyAlgorithm.ED25519, created_by="system_setup")
        print(f"    Generated active signing key: {sign_key_id}")

    try:
        hmac_key_id = ks.get_active_key(KeyPurpose.HMAC).id
        print(f"    Existing HMAC key: {hmac_key_id}")
    except Exception:
        hmac_key_id = ks.generate_key(KeyPurpose.HMAC, KeyAlgorithm.HMAC_SHA256, created_by="system_setup")
        print(f"    Generated active HMAC key: {hmac_key_id}")

    # 2. Seed synthetic users
    print("[*] Seeding synthetic users (Alice, Bob, Carol)...")
    users_to_seed = [
        ("alice_student", "alice@campus.local", "StudentPass123!Safe", "student"),
        ("bob_faculty", "bob@campus.local", "FacultyPass123!Safe", "faculty"),
        ("carol_admin", "carol@campus.local", "AdminPass123!Safe", "admin"),
    ]

    user_ids: dict[str, str] = {}
    for username, email, pwd, role in users_to_seed:
        try:
            uid = register_user(username, email, pwd, role=role, db_path=target_db)
            user_ids[username] = uid
            print(f"    Created {role} user: {username} (ID: {uid[:8]}...)")
        except Exception:
            # User already exists
            with db_session(target_db) as conn:
                row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
                if row:
                    user_ids[username] = row["id"]
                    print(f"    User {username} already exists.")

    # 3. Seed student marks
    print("[*] Seeding academic marks for Alice...")
    sample_marks = [
        ("CS301", "Network Security Protocols", 94, "Fall 2026"),
        ("CS302", "Applied Cryptography & PKI", 89, "Fall 2026"),
        ("CS303", "Application Security Architecture", 96, "Fall 2026"),
    ]
    with db_session(target_db) as conn:
        for code, name, score, sem in sample_marks:
            conn.execute(
                """
                INSERT INTO marks (student_id, faculty_id, course_code, course_name, score, semester, entered_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                """,
                (user_ids["alice_student"], user_ids["bob_faculty"], code, name, score, sem),
            )

    # 4. Seed sample encrypted & digitally signed academic document
    print("[*] Creating sample encrypted & digitally signed academic document...")
    doc_plaintext = (
        b"CAMPUSVAULT OFFICIAL SYLLABUS -- CS302: Applied Cryptography\n"
        b"Instructor: Dr. Bob Faculty\n"
        b"Semester: Fall 2026\n\n"
        b"Topics:\n"
        b"1. Symmetric vs Asymmetric Primitives\n"
        b"2. Authenticated Encryption with AES-256-GCM\n"
        b"3. Digital Signatures with Ed25519\n"
        b"4. Public Key Infrastructure and mTLS\n"
        b"5. Hash-Chained Audit Logs and Tamper Resistance\n"
    )

    doc_id = "doc-cs302-syllabus"
    doc_filename = "CS302_Syllabus.txt"
    files_dir = settings.files_dir
    files_dir.mkdir(parents=True, exist_ok=True)

    # A. Sign document
    sig_bundle = sign_document(
        plaintext=doc_plaintext,
        signing_key_id=sign_key_id,
        key_service=ks,
        signer_id=user_ids["bob_faculty"],
    )
    sig_rel_path = f"files/{doc_id}.sig"
    save_detached_signature(sig_bundle, files_dir / f"{doc_id}.sig")

    # B. Envelope encrypt document
    enc_bundle = encrypt_file_data(
        plaintext=doc_plaintext,
        key_service=ks,
        uploader_id=user_ids["bob_faculty"],
    )
    enc_file_rel_path = f"files/{doc_id}.enc"
    (files_dir / f"{doc_id}.enc").write_bytes(enc_bundle.serialize())

    # C. Record in documents table
    with db_session(target_db) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO documents
            (id, filename, uploader_id, encryption_key_id, file_path, signature_path, signing_key_id, content_hash, uploaded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                doc_id,
                doc_filename,
                user_ids["bob_faculty"],
                enc_bundle.kek_id,
                enc_file_rel_path,
                sig_rel_path,
                sign_key_id,
                sig_bundle["content_hash"],
            ),
        )

    print("[+] Database successfully seeded with keys, users, marks, and signed/encrypted document!")


if __name__ == "__main__":
    seed_all_data()
