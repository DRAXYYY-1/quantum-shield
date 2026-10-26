"""Interactive encrypted Send/Retrieve menu for Quantum-Shield's prototype."""
from __future__ import annotations

import os
import sys
import tempfile
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag

from quantum_shield.crypto import (
    CryptoConfigurationError,
    decrypt_for_recipient,
    encrypt_for_recipient,
    envelope_from_json,
    envelope_to_json,
)
from quantum_shield.distribution import (
    DEFAULT_CHUNK_BYTES,
    DistributionError,
    distribute_file,
    load_nodes,
    reconstruct_file,
)
from quantum_shield.identity import default_identity_path, load_or_create_identity


def _ask_path(prompt: str, default: str | None = None) -> Path:
    suffix = f" [{default}]" if default else ""
    answer = input(f"{prompt}{suffix}: ").strip()
    if not answer and default:
        answer = default
    if not answer:
        raise ValueError("a path is required")
    return Path(answer).expanduser()


def _ask_int(prompt: str, default: int, minimum: int = 1, maximum: int | None = None) -> int:
    answer = input(f"{prompt} [{default}]: ").strip()
    if not answer:
        return default
    try:
        value = int(answer)
    except ValueError as exc:
        raise ValueError(f"{prompt} must be a whole number") from exc
    if value < minimum or (maximum is not None and value > maximum):
        range_text = f"{minimum}..{maximum}" if maximum is not None else f"at least {minimum}"
        raise ValueError(f"{prompt} must be {range_text}")
    return value


def _atomic_write(target: Path, data: bytes) -> None:
    target = target.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, target)
        temp_name = ""
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def _send() -> None:
    source = _ask_path("File to send").resolve()
    if not source.is_file():
        raise ValueError("input must be an existing regular file")
    nodes_path = _ask_path("Node configuration", "nodes.json")
    nodes = load_nodes(nodes_path)
    default_manifest = str(Path("manifests") / f"{source.stem}.manifest.json")
    manifest_path = _ask_path("Save recovery manifest as", default_manifest)
    chunk_size = _ask_int("Chunk size in bytes", DEFAULT_CHUNK_BYTES)
    replicas = _ask_int("Copies of each chunk (replicas)", min(2, len(nodes)), maximum=len(nodes))

    # M1 encrypts the whole file before any bytes are sent to storage workers.
    public_key, _ = load_or_create_identity()
    crypto_file_id = uuid.uuid4().hex
    envelope = encrypt_for_recipient(source.read_bytes(), public_key, crypto_file_id)
    encrypted_bytes = envelope_to_json(envelope).encode("utf-8")

    with tempfile.TemporaryDirectory(prefix="quantum-shield-send-") as temp_dir:
        encrypted_path = Path(temp_dir) / "payload.qsenvelope"
        encrypted_path.write_bytes(encrypted_bytes)
        manifest = distribute_file(
            encrypted_path, nodes_path, manifest_path, chunk_size, replicas=replicas
        )

    print("\nSEND COMPLETE")
    print("Encryption: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM")
    print(f"File ID: {manifest['file_id']}")
    print(f"Chunks: {manifest['shard_count']} | Replicas per chunk: {replicas}")
    print(f"Recovery manifest: {manifest_path}")
    print(f"Local identity key: {default_identity_path()}")
    print("Keep the manifest and identity key safe. The same identity is required to decrypt.")


def _retrieve() -> None:
    manifest_path = _ask_path("Recovery manifest path").resolve()
    nodes_path = _ask_path("Node configuration", "nodes.json").resolve()
    load_nodes(nodes_path)
    output_path = _ask_path("Save decrypted file as").resolve()
    identity_path = default_identity_path().resolve()
    if output_path in {manifest_path, nodes_path, identity_path}:
        raise ValueError("output path must not overwrite the manifest, nodes configuration, or identity key")

    # Reconstruct only the encrypted envelope to a temporary file, then authenticate/decrypt it.
    with tempfile.TemporaryDirectory(prefix="quantum-shield-retrieve-") as temp_dir:
        encrypted_path = Path(temp_dir) / "payload.qsenvelope"
        reconstruct_file(manifest_path, nodes_path, encrypted_path)
        try:
            envelope = envelope_from_json(encrypted_path.read_text(encoding="utf-8"))
            _, private_key = load_or_create_identity()
            plaintext = decrypt_for_recipient(envelope, private_key, envelope["file_id"])
        except (InvalidTag, ValueError, CryptoConfigurationError) as exc:
            raise ValueError(
                "could not decrypt this file. Check that you are using the same Quantum-Shield "
                "identity key that was used when sending it, and that the encrypted data is intact."
            ) from exc
        _atomic_write(output_path, plaintext)

    print("\nRETRIEVE COMPLETE")
    print(f"Restored and decrypted file: {output_path}")


def main() -> int:
    print("Quantum-Shield — Encrypted Distributed File Menu")
    print("Research prototype: use non-sensitive test files only.\n")
    while True:
        print("1) Send a file (encrypt + distribute)")
        print("2) Retrieve a file (verify + decrypt)")
        print("3) Exit")
        try:
            choice = input("Choose an option [1-3]: ").strip()
            if choice == "1":
                _send()
            elif choice == "2":
                _retrieve()
            elif choice == "3":
                print("Goodbye.")
                return 0
            else:
                print("Please enter 1, 2, or 3.")
        except (DistributionError, OSError, ValueError, CryptoConfigurationError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return 130
        print()


if __name__ == "__main__":
    raise SystemExit(main())
