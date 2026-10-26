"""M2 storage worker: safe local shard storage and bounded framed protocol.

This is a research prototype, not a production service. M3 requires mutual TLS: the
server verifies client certificates, and clients verify the server certificate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

PROTOCOL_VERSION = 1
MAX_HEADER_BYTES = 16 * 1024
DEFAULT_MAX_SHARD_BYTES = 64 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class ProtocolError(Exception):
    """Malformed or unsupported protocol message."""


class StorageError(Exception):
    """A safe storage operation failed."""


def valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(ID_RE.fullmatch(value)) and value not in {".", ".."}


def recv_exact(sock: socket.socket, count: int) -> bytes:
    """Read exactly count bytes from a stream or fail on premature EOF."""
    if count < 0:
        raise ProtocolError("negative byte count")
    chunks = bytearray()
    while len(chunks) < count:
        piece = sock.recv(min(CHUNK_BYTES, count - len(chunks)))
        if not piece:
            raise ProtocolError("connection closed before frame was complete")
        chunks.extend(piece)
    return bytes(chunks)


def send_frame(sock: socket.socket, header: dict, payload: bytes = b"") -> None:
    header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(header_bytes) > MAX_HEADER_BYTES:
        raise ProtocolError("header too large")
    sock.sendall(struct.pack("!I", len(header_bytes)) + header_bytes + payload)


def recv_header(sock: socket.socket) -> dict:
    header_len = struct.unpack("!I", recv_exact(sock, 4))[0]
    if not 1 <= header_len <= MAX_HEADER_BYTES:
        raise ProtocolError("invalid header length")
    try:
        header = json.loads(recv_exact(sock, header_len).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid JSON header") from exc
    if not isinstance(header, dict):
        raise ProtocolError("header must be an object")
    if header.get("version") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    return header


@dataclass(frozen=True)
class StoreResult:
    shard_id: str
    size: int
    sha256: str


class ShardStore:
    """Store opaque shard bytes under generated safe names in one directory."""

    def __init__(self, root: str | Path, max_shard_bytes: int = DEFAULT_MAX_SHARD_BYTES):
        if max_shard_bytes < 1:
            raise ValueError("max_shard_bytes must be positive")
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.root.is_dir():
            raise StorageError("storage root is not a directory")
        self.max_shard_bytes = max_shard_bytes

    def _path(self, shard_id: object) -> Path:
        if not valid_id(shard_id):
            raise StorageError("invalid shard identifier")
        # The ID validation rejects separators; resolve check is defense in depth.
        path = (self.root / f"{shard_id}.shard").resolve()
        if path.parent != self.root:
            raise StorageError("invalid storage path")
        return path

    def put_stream(self, shard_id: str, size: int, expected_sha256: str, source: BinaryIO) -> StoreResult:
        path = self._path(shard_id)
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= self.max_shard_bytes:
            raise StorageError("invalid or oversized shard length")
        if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise StorageError("invalid SHA-256 digest")
        digest = hashlib.sha256()
        written = 0
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(mode="wb", dir=self.root, prefix=".incoming-", delete=False) as target:
                temp_name = target.name
                while written < size:
                    chunk = source.read(min(CHUNK_BYTES, size - written))
                    if not chunk:
                        raise StorageError("payload ended before declared length")
                    target.write(chunk)
                    digest.update(chunk)
                    written += len(chunk)
                target.flush()
                os.fsync(target.fileno())
            actual = digest.hexdigest()
            if actual != expected_sha256:
                raise StorageError("SHA-256 verification failed")
            # Atomic commit: incomplete/unverified data never appears at final path.
            os.replace(temp_name, path)
            temp_name = None
            return StoreResult(shard_id=shard_id, size=written, sha256=actual)
        except OSError as exc:
            raise StorageError("storage I/O failed") from exc
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass

    def put_bytes(self, shard_id: str, data: bytes, expected_sha256: str | None = None) -> StoreResult:
        import io
        return self.put_stream(shard_id, len(data), expected_sha256 or hashlib.sha256(data).hexdigest(), io.BytesIO(data))

    def get_bytes(self, shard_id: str) -> bytes:
        path = self._path(shard_id)
        try:
            size = path.stat().st_size
            if size > self.max_shard_bytes:
                raise StorageError("stored shard exceeds configured limit")
            with path.open("rb") as source:
                data = source.read(self.max_shard_bytes + 1)
            if len(data) != size or len(data) > self.max_shard_bytes:
                raise StorageError("stored shard changed during read")
            return data
        except FileNotFoundError as exc:
            raise StorageError("shard not found") from exc
        except OSError as exc:
            raise StorageError("storage I/O failed") from exc

    def delete(self, shard_id: str) -> bool:
        path = self._path(shard_id)
        try:
            path.unlink()
            return True
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise StorageError("storage I/O failed") from exc


def handle_client(conn: socket.socket, store: ShardStore) -> None:
    """Handle one framed STORE/GET request. M3 will add TLS/client auth."""
    conn.settimeout(10.0)
    try:
        header = recv_header(conn)
        op = header.get("op")
        if op == "STORE":
            shard_id = header.get("shard_id")
            size = header.get("size")
            digest = header.get("sha256")
            if not valid_id(shard_id):
                raise StorageError("invalid shard identifier")
            if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= store.max_shard_bytes:
                raise StorageError("invalid or oversized shard length")
            # Stream exact payload to a temporary file; no unbounded receive.
            class SocketReader:
                def __init__(self, sock: socket.socket):
                    self.sock = sock
                def read(self, count: int) -> bytes:
                    return recv_exact(self.sock, count)
            result = store.put_stream(shard_id, size, digest, SocketReader(conn))
            send_frame(conn, {"version": PROTOCOL_VERSION, "ok": True, "size": result.size, "sha256": result.sha256})
        elif op == "GET":
            shard_id = header.get("shard_id")
            data = store.get_bytes(shard_id)
            send_frame(conn, {"version": PROTOCOL_VERSION, "ok": True, "size": len(data),
                              "sha256": hashlib.sha256(data).hexdigest()}, data)
        else:
            raise ProtocolError("unsupported operation")
    except (ProtocolError, StorageError, socket.timeout, OSError, ValueError) as exc:
        # Return generic safe errors; do not reveal filesystem paths.
        try:
            send_frame(conn, {"version": PROTOCOL_VERSION, "ok": False, "error": str(exc)[:160]})
        except (OSError, ProtocolError):
            pass


def serve(host: str, port: int, root: Path, max_shard_bytes: int, certfile: str, keyfile: str, client_ca: str) -> None:
    import ssl
    from quantum_shield.storage.tls import server_context

    store = ShardStore(root, max_shard_bytes)
    tls_context = server_context(certfile, keyfile, client_ca)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(16)
        print(f"Quantum-Shield M3 mutual-TLS worker listening on {host}:{port}; storage={store.root}")
        print("Client certificates are required. Use only on a trusted network and firewall the port.")
        while True:
            raw_conn, _addr = server.accept()
            try:
                conn = tls_context.wrap_socket(raw_conn, server_side=True)
            except (ssl.SSLError, OSError):
                raw_conn.close()
                continue
            with conn:
                handle_client(conn, store)


def main() -> None:
    parser = argparse.ArgumentParser(description="Quantum-Shield M3 mutual-TLS shard storage worker")
    parser.add_argument("--host", default="127.0.0.1", help="interface to bind; use a LAN IP for LAN access")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--root", type=Path, default=Path("./qs-shards"))
    parser.add_argument("--max-shard-bytes", type=int, default=DEFAULT_MAX_SHARD_BYTES)
    parser.add_argument("--cert", required=True, help="server certificate PEM")
    parser.add_argument("--key", required=True, help="server private key PEM")
    parser.add_argument("--client-ca", required=True, help="CA certificate that issued trusted client certificates")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        serve(args.host, args.port, args.root, args.max_shard_bytes, args.cert, args.key, args.client_ca)
    except (OSError, ValueError) as exc:
        parser.error(f"could not start TLS worker: {exc}")


if __name__ == "__main__":
    main()
