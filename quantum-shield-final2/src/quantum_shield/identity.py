"""Local ML-KEM-768 identity storage for the Quantum-Shield prototype.

The private key is stored as raw bytes with owner-only permissions where the
operating system supports POSIX permissions. This is not password-encrypted.
Protect the account and back up the key securely; losing it makes stored files
encrypted to this identity unrecoverable.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm

from quantum_shield.crypto import CryptoConfigurationError, generate_recipient_keypair


def default_identity_path() -> Path:
    override = os.environ.get("QS_IDENTITY_KEY")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "quantum-shield" / "identity.mlkem768"


def load_or_create_identity(path: str | Path | None = None):
    """Return (public_key, private_key), creating a local identity on first use."""
    target = Path(path).expanduser() if path is not None else default_identity_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        try:
            raw = target.read_bytes()
        except OSError as exc:
            raise CryptoConfigurationError(f"cannot read identity key at {target}: {exc}") from exc
        try:
            from cryptography.hazmat.primitives.asymmetric import mlkem
            private_key = mlkem.MLKEM768PrivateKey.from_seed_bytes(raw)
            return private_key.public_key(), private_key
        except (ImportError, AttributeError, ValueError, UnsupportedAlgorithm) as exc:
            raise CryptoConfigurationError(
                f"identity key at {target} is invalid or this cryptography backend lacks ML-KEM support"
            ) from exc

    try:
        public_key, private_key = generate_recipient_keypair()
    except (CryptoConfigurationError, UnsupportedAlgorithm) as exc:
        raise CryptoConfigurationError(
            "ML-KEM-768 is unavailable in this cryptography/OpenSSL backend; install a supported cryptography release"
        ) from exc
    try:
        raw = private_key.private_bytes_raw()
    except AttributeError as exc:
        raise CryptoConfigurationError(
            "This cryptography backend does not support raw ML-KEM private-key serialization"
        ) from exc

    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        # Do not overwrite a key created concurrently by another process.
        try:
            os.link(temp_name, target)
        except FileExistsError:
            return load_or_create_identity(target)
        if os.name == "posix":
            os.chmod(target, 0o600)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
    return public_key, private_key
