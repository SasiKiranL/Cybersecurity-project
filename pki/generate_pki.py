"""PKI certificate and private key generation for CampusVault.

Generates:
1. Root Certificate Authority (Self-Signed, RSA 2048, 10-year validity)
2. Server TLS Certificate (Signed by CA, SAN: localhost & 127.0.0.1, 1-year validity)
3. Client mTLS Certificate (Signed by CA, CN: sensor-simulator-01, clientAuth, 1-year validity)
"""

from __future__ import annotations

import datetime
import ipaddress
import sys
from pathlib import Path
from typing import Tuple

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.config import get_settings


def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )


def save_key_to_pem(key: rsa.RSAPrivateKey, path: Path) -> None:
    """Save private key in PKCS#8 PEM format."""
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)


def save_cert_to_pem(cert: x509.Certificate, path: Path) -> None:
    """Save X.509 certificate in PEM format."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def generate_ca(
    common_name: str = "CampusVault Root CA",
    days_valid: int = 3650,
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Generate a self-signed Root CA certificate."""
    key = generate_rsa_key()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CampusVault Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def generate_server_cert(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    common_name: str = "localhost",
    days_valid: int = 365,
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Generate server TLS certificate signed by CA with SAN for localhost and 127.0.0.1."""
    key = generate_rsa_key()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CampusVault Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def generate_client_cert(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    common_name: str = "sensor-simulator-01",
    days_valid: int = 365,
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Generate client certificate signed by CA for mTLS authentication."""
    key = generate_rsa_key()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CampusVault IoT"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def generate_all_pki_artifacts() -> None:
    """Generate and save Root CA, Server TLS, and Client mTLS certificates."""
    settings = get_settings()

    print("[PKI] Generating Root CA...")
    ca_cert, ca_key = generate_ca()
    save_cert_to_pem(ca_cert, settings.ca_cert_path)
    save_key_to_pem(ca_key, settings.ca_key_path)

    print("[PKI] Generating Server Certificate...")
    srv_cert, srv_key = generate_server_cert(ca_cert, ca_key)
    save_cert_to_pem(srv_cert, settings.server_cert_path)
    save_key_to_pem(srv_key, settings.server_key_path)

    print("[PKI] Generating Client Certificate for mTLS...")
    cli_cert, cli_key = generate_client_cert(ca_cert, ca_key)
    save_cert_to_pem(cli_cert, settings.client_cert_path)
    save_key_to_pem(cli_key, settings.client_key_path)

    print("[PKI] Certificates and private keys successfully created in pki/ directory.")


if __name__ == "__main__":
    generate_all_pki_artifacts()
