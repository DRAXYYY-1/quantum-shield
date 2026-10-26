import base64
import copy

import pytest
from cryptography.exceptions import InvalidTag

from quantum_shield.crypto import (
    CryptoConfigurationError,
    EncryptedPayload,
    decrypt_for_recipient,
    decrypt_with_key,
    derive_file_key,
    encrypt_for_recipient,
    encrypt_with_key,
    envelope_from_json,
    envelope_to_json,
    generate_recipient_keypair,
)


def test_aes_gcm_round_trip_varied_payloads():
    key = bytes(range(32))
    for data in (b"", b"hello", bytes(range(256)), b"x" * 100_000):
        payload = encrypt_with_key(data, key, b"test-context")
        assert len(payload.nonce) == 12
        assert decrypt_with_key(payload, key, b"test-context") == data


def test_aes_gcm_detects_ciphertext_tampering():
    key = b"K" * 32
    payload = encrypt_with_key(b"sensitive test data", key, b"file-1")
    damaged = bytearray(payload.ciphertext)
    damaged[0] ^= 1
    with pytest.raises(InvalidTag):
        decrypt_with_key(EncryptedPayload(payload.nonce, bytes(damaged)), key, b"file-1")


def test_aes_gcm_authenticates_associated_data():
    key = b"K" * 32
    payload = encrypt_with_key(b"data", key, b"file-A")
    with pytest.raises(InvalidTag):
        decrypt_with_key(payload, key, b"file-B")


def test_key_derivation_is_context_bound():
    secret = b"S" * 32
    kem_ct = b"kem ciphertext fixture"
    assert derive_file_key(secret, kem_ct, "file-a") != derive_file_key(secret, kem_ct, "file-b")
    assert derive_file_key(secret, kem_ct, "file-a") != derive_file_key(secret, kem_ct + b"x", "file-a")


def test_key_derivation_rejects_wrong_secret_length():
    with pytest.raises(ValueError):
        derive_file_key(b"short", b"kem", "file-a")


def _kem_available():
    try:
        generate_recipient_keypair()
        return True
    except CryptoConfigurationError:
        return False
    except Exception:
        # A backend can expose the API but lack algorithm support.
        return False


@pytest.mark.skipif(not _kem_available(), reason="ML-KEM-768 requires supported cryptography >= 47 backend")
def test_mlkem_end_to_end_envelope_round_trip():
    public_key, private_key = generate_recipient_keypair()
    original = b"Quantum-Shield M1 end-to-end test\x00" * 200
    envelope = encrypt_for_recipient(original, public_key, "test-file-001")
    assert decrypt_for_recipient(envelope, private_key, "test-file-001") == original
    encoded = envelope_to_json(envelope)
    assert decrypt_for_recipient(envelope_from_json(encoded), private_key, "test-file-001") == original


@pytest.mark.skipif(not _kem_available(), reason="ML-KEM-768 requires supported cryptography >= 47 backend")
def test_mlkem_envelope_rejects_wrong_file_id_and_tampering():
    public_key, private_key = generate_recipient_keypair()
    envelope = encrypt_for_recipient(b"payload", public_key, "file-123")
    with pytest.raises(ValueError, match="file_id"):
        decrypt_for_recipient(envelope, private_key, "file-456")
    damaged = copy.deepcopy(envelope)
    raw = bytearray(base64.b64decode(damaged["ciphertext_b64"]))
    raw[0] ^= 1
    damaged["ciphertext_b64"] = base64.b64encode(raw).decode("ascii")
    with pytest.raises(InvalidTag):
        decrypt_for_recipient(damaged, private_key, "file-123")


def test_envelope_rejects_unknown_fields():
    # Structural validation should fail before cryptographic operations.
    fake = {
        "format": "quantum-shield-envelope", "version": 1,
        "algorithm": "ML-KEM-768+HKDF-SHA256+AES-256-GCM", "file_id": "x",
        "kem_ciphertext_b64": base64.b64encode(b"kem").decode(),
        "nonce_b64": base64.b64encode(b"0" * 12).decode(),
        "ciphertext_b64": base64.b64encode(b"0" * 16).decode(), "extra": "nope"
    }
    with pytest.raises(ValueError, match="unexpected fields"):
        envelope_to_json(fake)
