"""Small M1 command-line checks; no persistent key storage is performed."""
from __future__ import annotations

import argparse
import sys

from .crypto import (
    CryptoConfigurationError,
    decrypt_for_recipient,
    encrypt_for_recipient,
    generate_recipient_keypair,
)


def main() -> int:
    parser = argparse.ArgumentParser(prog="qs", description="Quantum-Shield M1 research tools")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("crypto-check", help="run an in-memory ML-KEM/AES-GCM round-trip")
    args = parser.parse_args()

    if args.command == "crypto-check":
        try:
            public_key, private_key = generate_recipient_keypair()
            original = b"Quantum-Shield M1 verification fixture\x00"
            envelope = encrypt_for_recipient(original, public_key, "m1-self-test")
            recovered = decrypt_for_recipient(envelope, private_key, "m1-self-test")
        except CryptoConfigurationError as exc:
            print(f"ML-KEM unavailable: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:  # Surface a failure without dumping secret material.
            print(f"Cryptographic self-test failed: {type(exc).__name__}", file=sys.stderr)
            return 1
        if recovered != original:
            print("Cryptographic self-test failed: recovered bytes differ", file=sys.stderr)
            return 1
        print("PASS: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM round-trip")
        print("Note: this self-test uses an in-memory keypair; no keys were saved.")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
