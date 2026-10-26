"""Mutual-TLS helpers for Quantum-Shield M3."""
from __future__ import annotations

import ssl
from pathlib import Path


def server_context(certfile: str | Path, keyfile: str | Path, client_ca: str | Path) -> ssl.SSLContext:
    """Create a TLS server context that requires a certificate from a trusted client CA."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    context.load_verify_locations(cafile=str(client_ca))
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def client_context(ca_file: str | Path, certfile: str | Path, keyfile: str | Path) -> ssl.SSLContext:
    """Create a client context that verifies the server and presents a client certificate."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    return context
