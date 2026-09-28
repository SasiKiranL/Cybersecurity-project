"""Assessment 3 Tests: Digital Signatures using Ed25519.

Verifies:
1. Document signing and successful signature verification.
2. Tamper detection: modifying document plaintext causes verification to fail.
3. Key binding: verifying against an incorrect signing key fails.
4. Detached .sig file persistence and loading round-trip.
5. Verification continuity: historical documents signed with retired keys remain verifiable.
"""

from __future__ import annotations

import pytest
from app.signatures import (
    sign_document,
    verify_document_signature,
    save_detached_signature,
    load_detached_signature,
)
from keyservice.models import KeyPurpose, KeyAlgorithm
from keyservice.service import KeyService


@pytest.fixture
def active_signing_service(key_service: KeyService) -> tuple[KeyService, str]:
    """Key service with an active Ed25519 signing key generated."""
    key_id = key_service.generate_key(
        purpose=KeyPurpose.SIGNING,
        algorithm=KeyAlgorithm.ED25519,
        created_by="faculty_bob",
    )
    return key_service, key_id


def test_signature_generation_and_verification(active_signing_service):
    """Test 1: Signing a document and verifying signature returns True."""
    ks, key_id = active_signing_service
    doc = b"Official transcript: Student Alice completed CS301 with Grade A."

    bundle = sign_document(doc, signing_key_id=key_id, key_service=ks, signer_id="faculty_bob")
    assert "signature_hex" in bundle
    assert "content_hash" in bundle

    is_valid = verify_document_signature(doc, bundle, key_service=ks)
    assert is_valid is True


def test_signature_tamper_detection(active_signing_service):
    """Test 2: Modifying signed document content fails verification."""
    ks, key_id = active_signing_service
    doc = b"Grade Report: CS101 Score 75."
    bundle = sign_document(doc, signing_key_id=key_id, key_service=ks)

    tampered_doc = b"Grade Report: CS101 Score 99."
    is_valid = verify_document_signature(tampered_doc, bundle, key_service=ks)
    assert is_valid is False


def test_signature_key_binding(active_signing_service):
    """Test 3: Signature cannot be verified with a different signing key."""
    ks, key_id = active_signing_service
    other_key_id = ks.generate_key(
        purpose=KeyPurpose.SIGNING,
        algorithm=KeyAlgorithm.ED25519,
        created_by="faculty_carol",
    )
    doc = b"Dean's list announcement."
    bundle = sign_document(doc, signing_key_id=key_id, key_service=ks)

    # Substitute key_id in bundle with other key
    bundle["signing_key_id"] = other_key_id
    is_valid = verify_document_signature(doc, bundle, key_service=ks)
    assert is_valid is False


def test_detached_signature_save_load(active_signing_service, tmp_path):
    """Test 4: Detached signature files are serialized and loaded accurately."""
    ks, key_id = active_signing_service
    doc = b"Important laboratory guidelines."
    bundle = sign_document(doc, signing_key_id=key_id, key_service=ks)

    sig_file = tmp_path / "doc.sig"
    save_detached_signature(bundle, sig_file)
    assert sig_file.exists()

    loaded_bundle = load_detached_signature(sig_file)
    assert loaded_bundle["signature_hex"] == bundle["signature_hex"]
    assert loaded_bundle["content_hash"] == bundle["content_hash"]
    assert verify_document_signature(doc, loaded_bundle, key_service=ks) is True


def test_signature_verification_on_retired_key(active_signing_service):
    """Test 5: Retiring a signing key does not break verification of past signed documents."""
    ks, key_id = active_signing_service
    doc = b"Degree certificate issued in Fall 2025."
    bundle = sign_document(doc, signing_key_id=key_id, key_service=ks)

    # Rotate / retire the key
    new_key_id = ks.rotate_key(key_id, caller="admin")

    # Document signature should still be verifiable using the public key of the retired key
    is_valid = verify_document_signature(doc, bundle, key_service=ks)
    assert is_valid is True
