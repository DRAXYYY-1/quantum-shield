"""Small mutual-TLS client for the M3 STORE/GET protocol."""
from __future__ import annotations

import argparse
import hashlib
import socket
from pathlib import Path

from quantum_shield.storage.tls import client_context
from quantum_shield.storage.worker import (
    PROTOCOL_VERSION, ProtocolError, recv_exact, recv_header, send_frame, valid_id,
)


def request(host: str, port: int, server_name: str, ca_file: str, certfile: str, keyfile: str,
            operation: str, shard_id: str, payload: bytes | None = None) -> tuple[dict, bytes]:
    if not valid_id(shard_id):
        raise ValueError("invalid shard identifier")
    context = client_context(ca_file, certfile, keyfile)
    with socket.create_connection((host, port), timeout=10.0) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as conn:
            conn.settimeout(30.0)
            if operation == "STORE":
                if payload is None:
                    raise ValueError("STORE requires a payload")
                header = {
                    "version": PROTOCOL_VERSION, "op": "STORE", "shard_id": shard_id,
                    "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                }
                send_frame(conn, header, payload)
            elif operation == "GET":
                send_frame(conn, {"version": PROTOCOL_VERSION, "op": "GET", "shard_id": shard_id})
            else:
                raise ValueError("operation must be STORE or GET")
            response = recv_header(conn)
            if response.get("ok") is not True:
                raise ProtocolError(str(response.get("error", "request failed")))
            if operation == "GET":
                size = response.get("size")
                if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                    raise ProtocolError("invalid response payload size")
                data = recv_exact(conn, size)
                digest = hashlib.sha256(data).hexdigest()
                if digest != response.get("sha256"):
                    raise ProtocolError("downloaded shard SHA-256 mismatch")
                return response, data
            return response, b""


def main() -> None:
    parser = argparse.ArgumentParser(description="Quantum-Shield M3 mutual-TLS client")
    parser.add_argument("operation", choices=("store", "get"))
    parser.add_argument("shard_id", help="safe shard identifier, not a file path")
    parser.add_argument("--host", required=True, help="worker host or IP address")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--server-name", required=True, help="DNS name in server certificate SAN")
    parser.add_argument("--ca", required=True, help="trusted CA certificate PEM")
    parser.add_argument("--cert", required=True, help="client certificate PEM")
    parser.add_argument("--key", required=True, help="client private key PEM")
    parser.add_argument("--file", required=True, type=Path, help="input file for store or output file for get")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        if args.operation == "store":
            payload = args.file.read_bytes()
            response, _ = request(args.host, args.port, args.server_name, args.ca, args.cert, args.key,
                                  "STORE", args.shard_id, payload)
            print(f"Stored shard {args.shard_id}: {response['size']} bytes; SHA-256 {response['sha256']}")
        else:
            response, payload = request(args.host, args.port, args.server_name, args.ca, args.cert, args.key,
                                        "GET", args.shard_id)
            args.file.parent.mkdir(parents=True, exist_ok=True)
            args.file.write_bytes(payload)
            print(f"Retrieved shard {args.shard_id}: {len(payload)} bytes -> {args.file}")
    except (OSError, ValueError, ProtocolError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
