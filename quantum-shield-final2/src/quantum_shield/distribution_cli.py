"""CLI for distributing and reconstructing files across M3 TLS workers."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from quantum_shield.distribution import (
    DEFAULT_CHUNK_BYTES, DistributionError, distribute_file, reconstruct_file,
)


def main() -> int:
    parser = argparse.ArgumentParser(prog="qs-distribute", description="Quantum-Shield M6 distributed storage tools")
    sub = parser.add_subparsers(dest="command", required=True)
    put = sub.add_parser("put", aliases=["send"], help="send: split and distribute a file to configured workers")
    put.add_argument("file", type=Path)
    put.add_argument("--nodes", required=True, type=Path, help="nodes JSON with each worker's TLS settings")
    put.add_argument("--manifest", required=True, type=Path, help="where to save the local recovery manifest")
    put.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_BYTES,
                     help=f"chunk bytes (default {DEFAULT_CHUNK_BYTES}; maximum 67108864)")
    put.add_argument("--replicas", type=int, default=2,
                     help="copies of each chunk on distinct workers (default 2; must not exceed worker count)")

    get = sub.add_parser("get", aliases=["retrieve"], help="retrieve: fetch shards and reconstruct a file")
    get.add_argument("--manifest", required=True, type=Path)
    get.add_argument("--nodes", required=True, type=Path)
    get.add_argument("--output", required=True, type=Path, help="destination file path")
    args = parser.parse_args()
    try:
        if args.command in ("put", "send"):
            manifest = distribute_file(args.file, args.nodes, args.manifest, args.chunk_size, replicas=args.replicas)
            print(f"Distributed {manifest['total_size']} bytes as {manifest['shard_count']} ordered chunks with {args.replicas} replicas each.")
            print(f"File ID: {manifest['file_id']}")
            print(f"Whole-file SHA-256: {manifest['whole_sha256']}")
            print(f"Recovery manifest: {args.manifest}")
            print("Keep the manifest safe. Replication tolerates some worker failures, but does not protect against losing every copy of a chunk.")
        else:
            result = reconstruct_file(args.manifest, args.nodes, args.output)
            print(f"Reconstructed file: {result}")
    except (DistributionError, OSError, ValueError) as exc:
        print(f"qs-distribute: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
