"""M4 ordered chunk distribution and reconstruction over the M3 mutual-TLS client.

This is a research prototype. Ordered chunks are not secret sharing or erasure coding.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any, Callable

from quantum_shield.storage.client import request as tls_request
from quantum_shield.storage.worker import DEFAULT_MAX_SHARD_BYTES, ProtocolError, valid_id

MANIFEST_VERSION = 1
SCHEME = "ordered-chunks-v1"
DEFAULT_CHUNK_BYTES = 4 * 1024 * 1024
MAX_CHUNKS = 100_000
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
NODE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class DistributionError(Exception):
    """Invalid configuration, manifest, or failed distribution/reconstruction."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_nodes(config_path: str | Path) -> list[dict[str, Any]]:
    """Load worker configuration; TLS file paths are relative to the config file."""
    path = Path(config_path).expanduser().resolve()
    try:
        raw = path.read_bytes()
        if len(raw) > 1024 * 1024:
            raise DistributionError("node configuration exceeds 1 MiB")
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DistributionError("could not read valid nodes JSON") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("nodes"), list) or not doc["nodes"]:
        raise DistributionError("nodes JSON must contain a non-empty 'nodes' array")
    if len(doc["nodes"]) > 256:
        raise DistributionError("at most 256 workers are supported")

    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in doc["nodes"]:
        if not isinstance(item, dict):
            raise DistributionError("each node must be a JSON object")
        node_id = item.get("id")
        host = item.get("host")
        port = item.get("port", 9999)
        server_name = item.get("server_name")
        if not isinstance(node_id, str) or not NODE_ID_RE.fullmatch(node_id) or node_id in seen:
            raise DistributionError("worker IDs must be unique safe identifiers")
        if not isinstance(host, str) or not host or len(host) > 253:
            raise DistributionError(f"invalid host for worker {node_id}")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise DistributionError(f"invalid port for worker {node_id}")
        if not isinstance(server_name, str) or not server_name:
            raise DistributionError(f"server_name is required for worker {node_id}")
        node = {"id": node_id, "host": host, "port": port, "server_name": server_name}
        for key in ("ca", "cert", "key"):
            value = item.get(key)
            if not isinstance(value, str) or not value:
                raise DistributionError(f"{key} path is required for worker {node_id}")
            candidate = Path(value).expanduser()
            if not candidate.is_absolute():
                candidate = path.parent / candidate
            node[key] = str(candidate.resolve())
        seen.add(node_id)
        result.append(node)
    return result


def _atomic_json(path: Path, document: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", suffix=".tmp", delete=False) as f:
            temp_name = f.name
            json.dump(document, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_name, path)
        temp_name = None
    except OSError as exc:
        raise DistributionError("could not safely write manifest") from exc
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def distribute_file(input_path: str | Path, nodes_path: str | Path, manifest_path: str | Path,
                   chunk_size: int = DEFAULT_CHUNK_BYTES,
                   request_fn: Callable[..., tuple[dict, bytes]] | None = None,
                   replicas: int = 1) -> dict[str, Any]:
    """Store each ordered chunk on ``replicas`` distinct workers.

    The Python API defaults to one replica for compatibility. The M5 CLI defaults to
    two. This is full chunk replication, not erasure coding. Failed attempts can leave
    orphaned remote copies; cleanup is not implemented in this prototype.
    """
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or not 1 <= chunk_size <= DEFAULT_MAX_SHARD_BYTES:
        raise DistributionError(f"chunk_size must be between 1 and {DEFAULT_MAX_SHARD_BYTES} bytes")
    nodes = load_nodes(nodes_path)
    if not isinstance(replicas, int) or isinstance(replicas, bool) or not 1 <= replicas <= len(nodes):
        raise DistributionError(f"replicas must be between 1 and the number of configured workers ({len(nodes)})")
    source_path = Path(input_path).expanduser().resolve()
    if not source_path.is_file():
        raise DistributionError("input must be an existing regular file")
    if request_fn is None:
        request_fn = tls_request

    file_id = uuid.uuid4().hex
    shards: list[dict[str, Any]] = []
    whole_digest = hashlib.sha256()
    total_size = 0
    try:
        before = source_path.stat()
        with source_path.open("rb") as source:
            index = 0
            while True:
                chunk = source.read(chunk_size)
                if not chunk and index > 0:
                    break
                # Represent an empty file with one valid empty shard.
                if not chunk and index == 0 and before.st_size != 0:
                    break
                if index >= MAX_CHUNKS:
                    raise DistributionError(f"file exceeds the {MAX_CHUNKS}-chunk prototype limit")
                whole_digest.update(chunk)
                total_size += len(chunk)
                shard_id = f"{file_id}-{index:06d}"
                digest = _sha256(chunk)
                # Rotate the first choice by chunk index to spread primary placement.
                candidates = nodes[index % len(nodes):] + nodes[:index % len(nodes)]
                stored_replicas: list[dict[str, Any]] = []
                replica_errors: list[str] = []
                for node in candidates:
                    if len(stored_replicas) >= replicas:
                        break
                    try:
                        response, _ = request_fn(
                            node["host"], node["port"], node["server_name"], node["ca"], node["cert"], node["key"],
                            "STORE", shard_id, chunk,
                        )
                        if response.get("size") != len(chunk) or response.get("sha256") != digest:
                            raise DistributionError(f"worker {node['id']} returned an unexpected STORE result")
                        stored_replicas.append({"node_id": node["id"], "shard_id": shard_id,
                                                "size": len(chunk), "sha256": digest})
                    except (OSError, ProtocolError, ValueError, DistributionError) as exc:
                        replica_errors.append(f"{node['id']}: {exc}")
                if len(stored_replicas) < replicas:
                    details = "; ".join(replica_errors[:3]) or "not enough workers accepted the shard"
                    raise DistributionError(
                        f"could not store chunk {index} on {replicas} distinct workers; "
                        f"stored {len(stored_replicas)} replicas ({details})"
                    )
                primary = stored_replicas[0]
                shards.append({"index": index, "shard_id": shard_id, "node_id": primary["node_id"],
                               "size": len(chunk), "sha256": digest, "replicas": stored_replicas})
                index += 1
                if len(chunk) < chunk_size:
                    break
        after = source_path.stat()
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise DistributionError("input file changed during distribution; manifest was not committed")
    except (OSError, ProtocolError, ValueError) as exc:
        if isinstance(exc, DistributionError):
            raise
        raise DistributionError(f"distribution failed: {exc}") from exc

    manifest = {
        "format": "quantum-shield-manifest", "version": MANIFEST_VERSION, "scheme": SCHEME,
        "file_id": file_id, "original_name": source_path.name, "total_size": total_size,
        "chunk_size": chunk_size, "whole_sha256": whole_digest.hexdigest(), "shard_count": len(shards),
        "shards": shards,
    }
    _atomic_json(Path(manifest_path), manifest)
    return manifest


def _load_manifest(manifest_path: str | Path) -> dict[str, Any]:
    path = Path(manifest_path).expanduser()
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_MANIFEST_BYTES:
            raise DistributionError("manifest exceeds 16 MiB")
        manifest = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DistributionError("could not read valid manifest JSON") from exc
    if not isinstance(manifest, dict):
        raise DistributionError("manifest must be a JSON object")
    if (manifest.get("format") != "quantum-shield-manifest" or manifest.get("version") != MANIFEST_VERSION
            or manifest.get("scheme") != SCHEME):
        raise DistributionError("unsupported manifest format, version, or chunking scheme")
    file_id = manifest.get("file_id")
    if not isinstance(file_id, str) or not re.fullmatch(r"[0-9a-f]{32}", file_id):
        raise DistributionError("invalid manifest file_id")
    total_size = manifest.get("total_size")
    count = manifest.get("shard_count")
    shards = manifest.get("shards")
    whole_hash = manifest.get("whole_sha256")
    if not isinstance(total_size, int) or isinstance(total_size, bool) or total_size < 0:
        raise DistributionError("invalid total_size in manifest")
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= MAX_CHUNKS:
        raise DistributionError("invalid shard_count in manifest")
    if not isinstance(shards, list) or len(shards) != count:
        raise DistributionError("manifest shard list does not match shard_count")
    if not isinstance(whole_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", whole_hash):
        raise DistributionError("invalid whole-file SHA-256 in manifest")
    expected_size = 0
    for index, shard in enumerate(shards):
        if not isinstance(shard, dict) or shard.get("index") != index:
            raise DistributionError("shards must have contiguous ordered indices")
        if not valid_id(shard.get("shard_id")):
            raise DistributionError("invalid shard identifier in manifest")
        if not isinstance(shard.get("node_id"), str) or not NODE_ID_RE.fullmatch(shard["node_id"]):
            raise DistributionError("invalid node_id in manifest")
        size = shard.get("size")
        digest = shard.get("sha256")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= DEFAULT_MAX_SHARD_BYTES:
            raise DistributionError("invalid shard size in manifest")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise DistributionError("invalid shard hash in manifest")
        replicas = shard.get("replicas")
        if replicas is not None:
            if not isinstance(replicas, list) or not replicas:
                raise DistributionError("replicas must be a non-empty list")
            replica_ids: set[str] = set()
            for replica in replicas:
                if not isinstance(replica, dict):
                    raise DistributionError("invalid replica entry in manifest")
                rid = replica.get("node_id")
                if not isinstance(rid, str) or not NODE_ID_RE.fullmatch(rid) or rid in replica_ids:
                    raise DistributionError("replica node IDs must be valid and distinct")
                if replica.get("shard_id") != shard["shard_id"] or replica.get("size") != size or replica.get("sha256") != digest:
                    raise DistributionError("replica metadata does not match its chunk")
                replica_ids.add(rid)
            if shard["node_id"] not in replica_ids:
                raise DistributionError("primary node must be listed among replicas")
        expected_size += size
    if expected_size != total_size:
        raise DistributionError("manifest shard sizes do not sum to total_size")
    if len({s["shard_id"] for s in shards}) != len(shards):
        raise DistributionError("duplicate shard IDs in manifest")
    return manifest


def reconstruct_file(manifest_path: str | Path, nodes_path: str | Path, output_path: str | Path,
                     request_fn: Callable[..., tuple[dict, bytes]] | None = None) -> Path:
    """Fetch every shard, verify its digest, then atomically reconstruct the file."""
    manifest = _load_manifest(manifest_path)
    nodes = load_nodes(nodes_path)
    node_map = {node["id"]: node for node in nodes}
    for shard in manifest["shards"]:
        replica_entries = shard.get("replicas") or [{"node_id": shard["node_id"], "shard_id": shard["shard_id"],
                                                       "size": shard["size"], "sha256": shard["sha256"]}]
        if not any(replica["node_id"] in node_map for replica in replica_entries):
            missing = ", ".join(replica["node_id"] for replica in replica_entries)
            raise DistributionError(f"all workers for shard {shard['shard_id']} are missing from nodes configuration ({missing})")
    if request_fn is None:
        request_fn = tls_request

    target = Path(output_path).expanduser().resolve()
    manifest_resolved = Path(manifest_path).expanduser().resolve()
    nodes_resolved = Path(nodes_path).expanduser().resolve()
    if target in {manifest_resolved, nodes_resolved}:
        raise DistributionError("output path must not overwrite the manifest or nodes configuration")
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    digest = hashlib.sha256()
    written = 0
    try:
        with tempfile.NamedTemporaryFile("wb", dir=target.parent, prefix=f".{target.name}.",
                                         suffix=".tmp", delete=False) as output:
            temp_name = output.name
            for shard in manifest["shards"]:
                replica_entries = shard.get("replicas") or [{"node_id": shard["node_id"], "shard_id": shard["shard_id"],
                                                               "size": shard["size"], "sha256": shard["sha256"]}]
                data = None
                errors: list[str] = []
                for replica in replica_entries:
                    node = node_map.get(replica["node_id"])
                    if node is None:
                        errors.append(f"{replica['node_id']}: not configured")
                        continue
                    try:
                        response, candidate_data = request_fn(
                            node["host"], node["port"], node["server_name"], node["ca"], node["cert"], node["key"],
                            "GET", replica["shard_id"],
                        )
                        if len(candidate_data) != shard["size"] or _sha256(candidate_data) != shard["sha256"]:
                            raise DistributionError("replica failed manifest integrity verification")
                        if response.get("size") != len(candidate_data) or response.get("sha256") != shard["sha256"]:
                            raise DistributionError("worker response does not match manifest")
                        data = candidate_data
                        break
                    except (OSError, ProtocolError, ValueError, DistributionError, KeyError) as exc:
                        errors.append(f"{replica['node_id']}: {exc}")
                if data is None:
                    raise DistributionError(f"no valid replica available for shard {shard['shard_id']}: {'; '.join(errors[:4])}")
                output.write(data)
                digest.update(data)
                written += len(data)
            output.flush()
            os.fsync(output.fileno())
        if written != manifest["total_size"] or digest.hexdigest() != manifest["whole_sha256"]:
            raise DistributionError("reconstructed file failed whole-file integrity verification")
        os.replace(temp_name, target)
        temp_name = None
        return target
    except (OSError, ProtocolError, ValueError) as exc:
        if isinstance(exc, DistributionError):
            raise
        raise DistributionError(f"reconstruction failed: {exc}") from exc
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


__all__ = ["DEFAULT_CHUNK_BYTES", "DistributionError", "distribute_file", "load_nodes", "reconstruct_file"]
