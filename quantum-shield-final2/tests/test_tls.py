import shutil
import ssl
import subprocess
from pathlib import Path

import pytest

from quantum_shield.storage.tls import client_context, server_context


def _run(*args):
    subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


@pytest.fixture
def certificates(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("openssl command is required to create temporary test certificates")
    root = tmp_path
    _run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "ca.key"),
         "-out", str(root / "ca.crt"), "-days", "2", "-subj", "/CN=QS Test CA",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-addext", "subjectKeyIdentifier=hash",
         "-addext", "authorityKeyIdentifier=keyid:always")
    for role, cn, eku in (("server", "localhost", "serverAuth"), ("client", "qs-test-client", "clientAuth")):
        _run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / f"{role}.key"),
             "-out", str(root / f"{role}.csr"), "-subj", f"/CN={cn}")
        ext = root / f"{role}.ext"
        if role == "server":
            ext.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=DNS:{cn}\nextendedKeyUsage={eku}\n")
        else:
            ext.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nauthorityKeyIdentifier=keyid,issuer\nextendedKeyUsage={eku}\n")
        _run("openssl", "x509", "-req", "-in", str(root / f"{role}.csr"), "-CA", str(root / "ca.crt"),
             "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-out", str(root / f"{role}.crt"),
             "-days", "2", "-extfile", str(ext))
    return root


def test_server_requires_trusted_client_certificate(certificates):
    ctx = server_context(certificates / "server.crt", certificates / "server.key", certificates / "ca.crt")
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_client_verifies_server_and_presents_certificate(certificates):
    ctx = client_context(certificates / "ca.crt", certificates / "client.crt", certificates / "client.key")
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_mutual_tls_store_get_round_trip(certificates, tmp_path):
    import socket
    import threading
    from quantum_shield.storage.client import request
    from quantum_shield.storage.worker import ShardStore, handle_client

    server_ctx = server_context(certificates / "server.crt", certificates / "server.key", certificates / "ca.crt")
    store = ShardStore(tmp_path / "shards")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    errors = []

    def serve_one():
        try:
            raw, _ = listener.accept()
            with raw:
                with server_ctx.wrap_socket(raw, server_side=True) as conn:
                    handle_client(conn, store)
        except Exception as exc:  # surfaced below for a useful test failure
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=serve_one, daemon=True)
    thread.start()
    payload = b"m3 mutual TLS round-trip payload"
    response, _ = request("127.0.0.1", port, "localhost", str(certificates / "ca.crt"),
                          str(certificates / "client.crt"), str(certificates / "client.key"),
                          "STORE", "tls-roundtrip", payload)
    assert response["ok"] is True
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert not errors

    # Serve a second request to verify retrieval over TLS too.
    listener2 = socket.socket()
    listener2.bind(("127.0.0.1", 0))
    listener2.listen(1)
    port2 = listener2.getsockname()[1]

    def serve_get():
        try:
            raw, _ = listener2.accept()
            with raw:
                with server_ctx.wrap_socket(raw, server_side=True) as conn:
                    handle_client(conn, store)
        except Exception as exc:
            errors.append(exc)
        finally:
            listener2.close()

    thread2 = threading.Thread(target=serve_get, daemon=True)
    thread2.start()
    response, retrieved = request("127.0.0.1", port2, "localhost", str(certificates / "ca.crt"),
                                  str(certificates / "client.crt"), str(certificates / "client.key"),
                                  "GET", "tls-roundtrip")
    assert response["ok"] is True
    assert retrieved == payload
    thread2.join(timeout=3)
    assert not thread2.is_alive()
    assert not errors
