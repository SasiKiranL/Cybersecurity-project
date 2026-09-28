"""VaultCTL: Standalone command-line authenticated encryption utility.

Uses AES-256-GCM authenticated encryption with scrypt key derivation.
Format:
[MAGIC(6 bytes: b"VAULT1")]
[SALT(32 bytes)]
[NONCE(12 bytes)]
[CIPHERTEXT + GCM_TAG]
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VAULT_MAGIC = b"VAULT1"


def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key using scrypt (N=32768, r=8, p=1)."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=32768,
        r=8,
        p=1,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_data(passphrase: str, plaintext: bytes) -> bytes:
    """Encrypt plaintext using scrypt + AES-256-GCM."""
    salt = os.urandom(32)
    nonce = os.urandom(12)
    key = derive_key_from_passphrase(passphrase, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return VAULT_MAGIC + salt + nonce + ciphertext


def decrypt_data(passphrase: str, encrypted_bytes: bytes) -> bytes:
    """Decrypt data using scrypt + AES-256-GCM. Verifies integrity tag."""
    if len(encrypted_bytes) < len(VAULT_MAGIC) + 32 + 12 + 16:
        raise ValueError("File is too short to be a valid vault archive.")

    if not encrypted_bytes.startswith(VAULT_MAGIC):
        raise ValueError("Invalid file header: magic mismatch.")

    offset = len(VAULT_MAGIC)
    salt = encrypted_bytes[offset : offset + 32]
    offset += 32
    nonce = encrypted_bytes[offset : offset + 12]
    offset += 12
    ciphertext = encrypted_bytes[offset:]

    key = derive_key_from_passphrase(passphrase, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Decryption failed: incorrect passphrase or corrupted data.")


def inspect_archive(encrypted_bytes: bytes) -> dict:
    """Inspect archive header metadata without decrypting."""
    if len(encrypted_bytes) < len(VAULT_MAGIC) + 32 + 12:
        raise ValueError("File too short.")
    if not encrypted_bytes.startswith(VAULT_MAGIC):
        raise ValueError("Header magic mismatch.")

    offset = len(VAULT_MAGIC)
    salt = encrypted_bytes[offset : offset + 32]
    offset += 32
    nonce = encrypted_bytes[offset : offset + 12]
    offset += 12
    ciphertext = encrypted_bytes[offset:]

    return {
        "magic": VAULT_MAGIC.decode("ascii"),
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        "ciphertext_bytes": len(ciphertext),
        "total_file_bytes": len(encrypted_bytes),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="CampusVault Standalone Encryption CLI (VaultCTL)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument("-i", "--input", required=True, help="Input plaintext file")
    enc_parser.add_argument("-o", "--output", required=True, help="Output ciphertext file")
    enc_parser.add_argument("-p", "--passphrase", help="Passphrase (prompts if omitted)")

    # Decrypt
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument("-i", "--input", required=True, help="Input ciphertext file")
    dec_parser.add_argument("-o", "--output", required=True, help="Output plaintext file")
    dec_parser.add_argument("-p", "--passphrase", help="Passphrase (prompts if omitted)")

    # Inspect
    insp_parser = subparsers.add_parser("inspect", help="Inspect vault file header")
    insp_parser.add_argument("-i", "--input", required=True, help="Input vault file")

    args = parser.parse_args()

    if args.command == "encrypt":
        in_path = Path(args.input)
        out_path = Path(args.output)
        if not in_path.exists():
            print(f"Error: Input file '{in_path}' does not exist.", file=sys.stderr)
            sys.exit(1)

        passphrase = args.passphrase
        if not passphrase:
            passphrase = getpass.getpass("Enter encryption passphrase: ")
            confirm = getpass.getpass("Confirm encryption passphrase: ")
            if passphrase != confirm:
                print("Error: Passphrases do not match.", file=sys.stderr)
                sys.exit(1)

        plaintext = in_path.read_bytes()
        encrypted = encrypt_data(passphrase, plaintext)
        out_path.write_bytes(encrypted)
        print(f"Successfully encrypted '{in_path}' to '{out_path}' ({len(encrypted)} bytes).")

    elif args.command == "decrypt":
        in_path = Path(args.input)
        out_path = Path(args.output)
        if not in_path.exists():
            print(f"Error: Input file '{in_path}' does not exist.", file=sys.stderr)
            sys.exit(1)

        passphrase = args.passphrase
        if not passphrase:
            passphrase = getpass.getpass("Enter decryption passphrase: ")

        encrypted = in_path.read_bytes()
        try:
            decrypted = decrypt_data(passphrase, encrypted)
            out_path.write_bytes(decrypted)
            print(f"Successfully decrypted '{in_path}' to '{out_path}' ({len(decrypted)} bytes).")
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "inspect":
        in_path = Path(args.input)
        if not in_path.exists():
            print(f"Error: Input file '{in_path}' does not exist.", file=sys.stderr)
            sys.exit(1)

        data = in_path.read_bytes()
        try:
            info = inspect_archive(data)
            print("VaultCTL Archive Inspection:")
            print(f"  Header Magic:      {info['magic']}")
            print(f"  Salt (hex):        {info['salt_hex']}")
            print(f"  Nonce (hex):       {info['nonce_hex']}")
            print(f"  Ciphertext size:   {info['ciphertext_bytes']} bytes")
            print(f"  Total file size:   {info['total_file_bytes']} bytes")
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
