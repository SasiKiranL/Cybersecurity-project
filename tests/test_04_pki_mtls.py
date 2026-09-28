"""Assessment 4 Tests: PKI and Mutual TLS (mTLS).

Verifies:
1. Root CA generation with correct X.509 v3 basic constraints (CA:TRUE) and self-signature.
2. Server TLS certificate signed by Root CA with SAN for localhost and 127.0.0.1.
3. Client mTLS certificate signed by Root CA with clientAuth extended key usage.
4. Certificate validity periods and date check verification.
5. X.509 certificate chain validation and rejection of untrusted certificates.
"""

from __future__ import annotations

import datetime
import ipaddress
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from pki.generate_pki import generate_ca, generate_server_cert, generate_client_cert


def test_ca_cert_generation_and_properties():
    """Test 1: Root CA certificate has CA:TRUE, keyCertSign, and valid self-signature."""
    ca_cert, ca_key = generate_ca(common_name="Test Campus Root CA", days_valid=365)

    # 1. Subject and Issuer must match (self-signed)
    assert ca_cert.subject == ca_cert.issuer

    # 2. Basic constraints must have ca=True
    bc = ca_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    assert bc.ca is True

    # 3. Key usage must permit cert signing
    ku = ca_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    assert ku.key_cert_sign is True

    # 4. Verify cryptographic self-signature
    ca_cert.public_key().verify(
        ca_cert.signature,
        ca_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        ca_cert.signature_hash_algorithm,
    )


def test_server_cert_generation_and_san():
    """Test 2: Server certificate is signed by Root CA and has SAN for localhost & 127.0.0.1."""
    ca_cert, ca_key = generate_ca()
    srv_cert, srv_key = generate_server_cert(ca_cert, ca_key, common_name="localhost")

    # 1. Issuer matches CA subject
    assert srv_cert.issuer == ca_cert.subject

    # 2. Verify signature with CA public key
    ca_cert.public_key().verify(
        srv_cert.signature,
        srv_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        srv_cert.signature_hash_algorithm,
    )

    # 3. Verify SAN extension
    san = srv_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    dns_names = san.get_values_for_type(x509.DNSName)
    ip_addrs = san.get_values_for_type(x509.IPAddress)

    assert "localhost" in dns_names
    assert ipaddress.IPv4Address("127.0.0.1") in ip_addrs

    # 4. Extended Key Usage must include serverAuth
    eku = srv_cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku


def test_client_cert_generation_and_client_auth():
    """Test 3: Client mTLS certificate is signed by CA and configured for clientAuth."""
    ca_cert, ca_key = generate_ca()
    cli_cert, cli_key = generate_client_cert(ca_cert, ca_key, common_name="sensor-simulator-01")

    # 1. Issuer matches CA subject
    assert cli_cert.issuer == ca_cert.subject

    # 2. Verify signature with CA public key
    ca_cert.public_key().verify(
        cli_cert.signature,
        cli_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cli_cert.signature_hash_algorithm,
    )

    # 3. Extended Key Usage must include clientAuth
    eku = cli_cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku


def test_cert_expiry_and_validity_window():
    """Test 4: Generated certificates are valid at current time and span expected duration."""
    ca_cert, ca_key = generate_ca(days_valid=30)
    srv_cert, srv_key = generate_server_cert(ca_cert, ca_key, days_valid=14)

    now = datetime.datetime.now(datetime.timezone.utc)
    assert srv_cert.not_valid_before_utc <= now <= srv_cert.not_valid_after_utc
    duration = srv_cert.not_valid_after_utc - srv_cert.not_valid_before_utc
    assert duration.days >= 14


def test_mtls_handshake_verification_logic():
    """Test 5: Valid CA verifies legitimate client cert, but rejects untrusted rogue cert."""
    ca_cert, ca_key = generate_ca()
    valid_cli_cert, _ = generate_client_cert(ca_cert, ca_key)

    # Rogue CA generates a rogue cert
    rogue_ca_cert, rogue_ca_key = generate_ca(common_name="Rogue Hacker CA")
    rogue_cli_cert, _ = generate_client_cert(rogue_ca_cert, rogue_ca_key)

    # 1. Verification of legitimate cert under trusted CA succeeds
    ca_cert.public_key().verify(
        valid_cli_cert.signature,
        valid_cli_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        valid_cli_cert.signature_hash_algorithm,
    )

    # 2. Verification of rogue cert under trusted CA fails cryptographically
    with pytest.raises(Exception):
        ca_cert.public_key().verify(
            rogue_cli_cert.signature,
            rogue_cli_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            rogue_cli_cert.signature_hash_algorithm,
        )
