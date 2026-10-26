"""Reproducible local benchmarks for Quantum-Shield's chunking/hash pipeline.

These benchmarks intentionally do not contact workers. They measure local CPU and
memory-copy overhead, and estimate replica storage overhead; network performance must
be measured separately against real TLS workers.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import statistics
import time
from pathlib import Path
from typing import Any

MAX_BENCH_BYTES = 256 * 1024 * 1024
VALID_CHUNK_SIZES = (64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024)


def _positive_int(value: str) -> int:
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if result < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return result


def benchmark_case(size_bytes: int, chunk_size: int, replicas: int = 2, repeats: int = 3) -> dict[str, Any]:
    """Benchmark in-memory chunk/hash/reassemble work using deterministic data."""
    if not 1 <= size_bytes <= MAX_BENCH_BYTES:
        raise ValueError(f"size_bytes must be 1..{MAX_BENCH_BYTES}")
    if not 1 <= chunk_size <= 64 * 1024 * 1024:
        raise ValueError("chunk_size must be 1..67108864")
    if not 1 <= replicas <= 16:
        raise ValueError("replicas must be 1..16")
    if not 1 <= repeats <= 20:
        raise ValueError("repeats must be 1..20")

    # Generate once, outside the timed section, so results focus on chunk/hash work.
    source = bytes((i * 31 + 7) % 256 for i in range(size_bytes))
    expected_hash = hashlib.sha256(source).hexdigest()
    timings: list[float] = []
    digest_seconds: list[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        chunks = [source[offset:offset + chunk_size] for offset in range(0, len(source), chunk_size)]
        per_chunk_hashes = [hashlib.sha256(chunk).hexdigest() for chunk in chunks]
        rebuilt = b"".join(chunks)
        elapsed = time.perf_counter() - start
        if rebuilt != source or hashlib.sha256(rebuilt).hexdigest() != expected_hash:
            raise RuntimeError("benchmark integrity check failed")
        if any(hashlib.sha256(chunk).hexdigest() != digest for chunk, digest in zip(chunks, per_chunk_hashes)):
            raise RuntimeError("chunk integrity check failed")
        timings.append(elapsed)
        digest_start = time.perf_counter()
        hashlib.sha256(source).digest()
        digest_seconds.append(time.perf_counter() - digest_start)

    median_s = statistics.median(timings)
    chunk_count = max(1, (size_bytes + chunk_size - 1) // chunk_size)
    return {
        "benchmark_type": "local_in_memory_no_network",
        "size_bytes": size_bytes,
        "chunk_size_bytes": chunk_size,
        "chunk_count": chunk_count,
        "replicas": replicas,
        "estimated_storage_bytes": size_bytes * replicas,
        "estimated_replication_overhead_bytes": size_bytes * (replicas - 1),
        "median_chunk_hash_reassemble_seconds": round(median_s, 9),
        "median_whole_file_hash_seconds": round(statistics.median(digest_seconds), 9),
        "effective_local_mib_per_second": round((size_bytes / (1024 * 1024)) / median_s, 3) if median_s else None,
        "repeats": repeats,
        "verified_sha256": expected_hash,
        "integrity_verified": True,
    }


def run_benchmarks(sizes: list[int], chunk_sizes: list[int], replicas: int = 2,
                   repeats: int = 3) -> list[dict[str, Any]]:
    if not sizes or not chunk_sizes:
        raise ValueError("at least one size and chunk size are required")
    if len(sizes) * len(chunk_sizes) > 100:
        raise ValueError("at most 100 benchmark combinations are allowed")
    return [benchmark_case(size, chunk, replicas, repeats) for size in sizes for chunk in chunk_sizes]


def _write_results(path: Path, results: list[dict[str, Any]], fmt: str) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        path.write_text(json.dumps({"title": "Quantum-Shield M6 local benchmark", "results": results}, indent=2) + "\n", encoding="utf-8")
    else:
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
            writer.writeheader()
            writer.writerows(results)


def main() -> int:
    parser = argparse.ArgumentParser(prog="qs-benchmark", description="Benchmark Quantum-Shield's local chunk/hash pipeline (no network traffic).")
    parser.add_argument("--sizes-mib", nargs="+", type=_positive_int, default=[1, 10], help="input sizes in MiB (maximum 256)")
    parser.add_argument("--chunk-kib", nargs="+", type=_positive_int, default=[256, 1024, 4096], help="chunk sizes in KiB (maximum 65536)")
    parser.add_argument("--replicas", type=_positive_int, default=2, help="replica count used for storage-overhead estimate (1..16)")
    parser.add_argument("--repeats", type=_positive_int, default=3, help="repeats per combination (1..20)")
    parser.add_argument("--output", type=Path, default=Path("m6-benchmark.json"), help="output .json or .csv")
    args = parser.parse_args()
    try:
        sizes = [x * 1024 * 1024 for x in args.sizes_mib]
        chunks = [x * 1024 for x in args.chunk_kib]
        if any(x > MAX_BENCH_BYTES for x in sizes):
            raise ValueError("--sizes-mib values must not exceed 256")
        if any(x > 64 * 1024 for x in args.chunk_kib):
            raise ValueError("--chunk-kib values must not exceed 65536")
        if args.replicas > 16 or args.repeats > 20:
            raise ValueError("replicas must be <=16 and repeats <=20")
        fmt = args.output.suffix.lower().lstrip(".")
        if fmt not in {"json", "csv"}:
            raise ValueError("output file must end in .json or .csv")
        results = run_benchmarks(sizes, chunks, args.replicas, args.repeats)
        _write_results(args.output, results, fmt)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    print(f"Completed {len(results)} local benchmark cases; integrity checks passed.")
    print(f"Results: {args.output.resolve()}")
    print("Note: these are in-memory results, not end-to-end LAN/TLS throughput measurements.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
