"""M1 cryptographic core: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM.

The ML-KEM API requires cryptography >= 47.0.0. The symmetric helpers can be
unit-tested independently, but the end-to-end KEM flow requires a supported
cryptography/OpenSSL backend.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

FORMAT_VERSION = 1
KEY_BYTES = 32
NONCE_BYTES = 12
_INFO_PREFIX = b"Quantum-Shield/M1/file-key/v1\x00"


class CryptoConfigurationError(RuntimeError):
    """Raised when the required ML-KEM implementation is unavailable."""


@dataclass(frozen=True)
class EncryptedPayload:
    nonce: bytes
    ciphertext: bytes  # AES-GCM ciphertext with authentication tag appended.


def derive_file_key(shared_secret: bytes, kem_ciphertext: bytes, file_id: str) -> bytes:
    """Derive a per-file AES key from an ML-KEM shared secret.

    The KEM ciphertext contributes to the salt; file_id provides domain/context
    separation and is also authenticated as AES-GCM associated data.
    """
    if len(shared_secret) != 32:
        raise ValueError("ML-KEM-768 shared secret must be exactly 32 bytes")
    if not file_id or len(file_id.encode("utf-8")) > 256:
        raise ValueError("file_id must be non-empty and at most 256 UTF-8 bytes")
    salt = hashlib.sha256(b"QS-KEM-SALT\x00" + kem_ciphertext).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        info=_INFO_PREFIX + file_id.encode("utf-8"),
    ).derive(shared_secret)


def encrypt_with_key(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> EncryptedPayload:
    """Encrypt bytes using AES-256-GCM with a fresh 96-bit nonce."""
    if len(key) != KEY_BYTES:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return EncryptedPayload(nonce=nonce, ciphertext=ciphertext)


def decrypt_with_key(payload: EncryptedPayload, key: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt and authenticate an AES-GCM payload; tampering raises InvalidTag."""
    if len(key) != KEY_BYTES:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    if len(payload.nonce) != NONCE_BYTES:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    return AESGCM(key).decrypt(payload.nonce, payload.ciphertext, associated_data)


def _mlkem_module():
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem
        return mlkem
    except ImportError as exc:
        raise CryptoConfigurationError(
            "ML-KEM API not found. Install a compatible cryptography release (>=47.0.0) "
            "and verify that its backend supports ML-KEM-768."
        ) from exc


def generate_recipient_keypair():
    """Generate an ML-KEM-768 private key and its public key."""
    mlkem = _mlkem_module()
    private_key = mlkem.MLKEM768PrivateKey.generate()
    return private_key.public_key(), private_key


def encrypt_for_recipient(plaintext: bytes, public_key: Any, file_id: str) -> dict[str, Any]:
    """Create a JSON-compatible envelope for a recipient's ML-KEM public key."""
    if not file_id or len(file_id.encode("utf-8")) > 256:
        raise ValueError("file_id must be non-empty and at most 256 UTF-8 bytes")
    shared_secret, kem_ciphertext = public_key.encapsulate()
    key = derive_file_key(shared_secret, kem_ciphertext, file_id)
    aad = _associated_data(file_id)
    payload = encrypt_with_key(plaintext, key, aad)
    return {
        "format": "quantum-shield-envelope",
        "version": FORMAT_VERSION,
        "algorithm": "ML-KEM-768+HKDF-SHA256+AES-256-GCM",
        "file_id": file_id,
        "kem_ciphertext_b64": _b64e(kem_ciphertext),
        "nonce_b64": _b64e(payload.nonce),
        "ciphertext_b64": _b64e(payload.ciphertext),
    }


def decrypt_for_recipient(envelope: dict[str, Any], private_key: Any, expected_file_id: str) -> bytes:
    """Validate an envelope, decapsulate, then authenticate/decrypt its contents."""
    _validate_envelope(envelope, expected_file_id)
    kem_ciphertext = _b64d(envelope["kem_ciphertext_b64"])
    nonce = _b64d(envelope["nonce_b64"])
    ciphertext = _b64d(envelope["ciphertext_b64"])
    shared_secret = private_key.decapsulate(kem_ciphertext)
    key = derive_file_key(shared_secret, kem_ciphertext, expected_file_id)
    return decrypt_with_key(
        EncryptedPayload(nonce=nonce, ciphertext=ciphertext), key, _associated_data(expected_file_id)
    )


def envelope_to_json(envelope: dict[str, Any]) -> str:
    """Serialize an envelope deterministically for storage or test fixtures."""
    _validate_envelope_shape(envelope)
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"))


def envelope_from_json(raw: str) -> dict[str, Any]:
    """Parse and structurally validate an envelope JSON string."""
    try:
        obj = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid envelope JSON") from exc
    if not isinstance(obj, dict):
        raise ValueError("Envelope must be a JSON object")
    _validate_envelope_shape(obj)
    return obj


def _validate_envelope(envelope: dict[str, Any], expected_file_id: str) -> None:
    _validate_envelope_shape(envelope)
    if envelope["file_id"] != expected_file_id:
        raise ValueError("Envelope file_id does not match expected file_id")


def _validate_envelope_shape(envelope: dict[str, Any]) -> None:
    required = {
        "format", "version", "algorithm", "file_id", "kem_ciphertext_b64", "nonce_b64", "ciphertext_b64"
    }
    if not isinstance(envelope, dict) or set(envelope) != required:
        raise ValueError("Envelope has missing or unexpected fields")
    if envelope["format"] != "quantum-shield-envelope" or envelope["version"] != FORMAT_VERSION:
        raise ValueError("Unsupported envelope format or version")
    if envelope["algorithm"] != "ML-KEM-768+HKDF-SHA256+AES-256-GCM":
        raise ValueError("Unsupported algorithm suite")
    if not isinstance(envelope["file_id"], str) or not envelope["file_id"]:
        raise ValueError("Invalid file_id")
    if len(envelope["file_id"].encode("utf-8")) > 256:
        raise ValueError("file_id is too long")
    for name in ("kem_ciphertext_b64", "nonce_b64", "ciphertext_b64"):
        if not isinstance(envelope[name], str):
            raise ValueError(f"{name} must be a base64 string")
        _b64d(envelope[name])
    if len(_b64d(envelope["nonce_b64"])) != NONCE_BYTES:
        raise ValueError("Invalid nonce length")
    if len(_b64d(envelope["ciphertext_b64"])) < 16:
        raise ValueError("Ciphertext is too short to contain a GCM tag")


def _associated_data(file_id: str) -> bytes:
    return b"Quantum-Shield/M1/AAD/v1\x00" + file_id.encode("utf-8")


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("Invalid base64 field in envelope") from exc


__all__ = [
    "CryptoConfigurationError", "EncryptedPayload", "decrypt_for_recipient", "decrypt_with_key",
    "derive_file_key", "encrypt_for_recipient", "encrypt_with_key", "envelope_from_json",
    "envelope_to_json", "generate_recipient_keypair",
]
