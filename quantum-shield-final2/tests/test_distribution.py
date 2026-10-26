import hashlib
import json
from pathlib import Path

import pytest

from quantum_shield.distribution import (
    DistributionError, distribute_file, reconstruct_file,
)


def make_nodes(tmp_path: Path, count: int = 2) -> Path:
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    for name in ("ca.crt", "client.crt", "client.key"):
        (cert_dir / name).write_text("test fixture only")
    nodes = []
    for i in range(count):
        nodes.append({
            "id": f"worker-{i}", "host": f"worker-{i}.test", "port": 9999,
            "server_name": f"worker-{i}.test", "ca": "certs/ca.crt",
            "cert": "certs/client.crt", "key": "certs/client.key",
        })
    path = tmp_path / "nodes.json"
    path.write_text(json.dumps({"nodes": nodes}))
    return path


class FakeTLS:
    def __init__(self):
        self.data = {}
        self.fail_store = False
        self.corrupt_get = False
        self.fail_store_hosts = set()
        self.fail_get_hosts = set()

    def __call__(self, host, port, server_name, ca, cert, key, operation, shard_id, payload=None):
        store_key = (host, shard_id)
        if operation == "STORE":
            if self.fail_store or host in self.fail_store_hosts:
                raise OSError("simulated worker failure")
            self.data[store_key] = payload
            return ({"ok": True, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}, b"")
        if host in self.fail_get_hosts:
            raise OSError("simulated unavailable worker")
        data = self.data[store_key]
        if self.corrupt_get:
            data += b"tampered"
        return ({"ok": True, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}, data)


def test_distribute_reconstruct_across_multiple_workers(tmp_path):
    nodes = make_nodes(tmp_path, 3)
    original = (b"quantum-shield-M4\x00" * 43) + b"tail"
    source = tmp_path / "original.bin"
    source.write_bytes(original)
    manifest_path = tmp_path / "file.manifest.json"
    restored = tmp_path / "restored.bin"
    fake = FakeTLS()

    manifest = distribute_file(source, nodes, manifest_path, chunk_size=31, request_fn=fake)
    assert manifest["shard_count"] > 3
    assert len({shard["node_id"] for shard in manifest["shards"]}) == 3
    assert manifest["scheme"] == "ordered-chunks-v1"
    reconstruct_file(manifest_path, nodes, restored, request_fn=fake)
    assert restored.read_bytes() == original


def test_empty_file_round_trip(tmp_path):
    nodes = make_nodes(tmp_path, 1)
    source = tmp_path / "empty.bin"
    source.write_bytes(b"")
    manifest_path = tmp_path / "empty.manifest.json"
    restored = tmp_path / "restored-empty.bin"
    fake = FakeTLS()
    manifest = distribute_file(source, nodes, manifest_path, chunk_size=12, request_fn=fake)
    assert manifest["shard_count"] == 1
    assert manifest["total_size"] == 0
    reconstruct_file(manifest_path, nodes, restored, request_fn=fake)
    assert restored.read_bytes() == b""


def test_corrupted_shard_does_not_create_output(tmp_path):
    nodes = make_nodes(tmp_path)
    source = tmp_path / "original.bin"
    source.write_bytes(b"abcdef" * 30)
    manifest_path = tmp_path / "manifest.json"
    fake = FakeTLS()
    distribute_file(source, nodes, manifest_path, chunk_size=15, request_fn=fake)
    fake.corrupt_get = True
    output = tmp_path / "should-not-exist.bin"
    with pytest.raises(DistributionError, match="no valid replica available"):
        reconstruct_file(manifest_path, nodes, output, request_fn=fake)
    assert not output.exists()


def test_missing_worker_is_reported_before_retrieval(tmp_path):
    nodes = make_nodes(tmp_path, 2)
    source = tmp_path / "original.bin"
    source.write_bytes(b"some bytes to distribute")
    manifest_path = tmp_path / "manifest.json"
    fake = FakeTLS()
    distribute_file(source, nodes, manifest_path, chunk_size=4, request_fn=fake)
    one_node = make_nodes(tmp_path / "other", 1)
    with pytest.raises(DistributionError, match="all workers for shard"):
        reconstruct_file(manifest_path, one_node, tmp_path / "out.bin", request_fn=fake)


def test_failed_store_does_not_commit_manifest(tmp_path):
    nodes = make_nodes(tmp_path)
    source = tmp_path / "original.bin"
    source.write_bytes(b"abcdef")
    manifest_path = tmp_path / "manifest.json"
    fake = FakeTLS()
    fake.fail_store = True
    with pytest.raises(DistributionError, match="could not store chunk|distribution failed"):
        distribute_file(source, nodes, manifest_path, chunk_size=3, request_fn=fake)
    assert not manifest_path.exists()


def test_manifest_size_tampering_is_rejected(tmp_path):
    nodes = make_nodes(tmp_path)
    source = tmp_path / "original.bin"
    source.write_bytes(b"abcdef")
    manifest_path = tmp_path / "manifest.json"
    fake = FakeTLS()
    distribute_file(source, nodes, manifest_path, chunk_size=3, request_fn=fake)
    manifest = json.loads(manifest_path.read_text())
    manifest["total_size"] += 1
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(DistributionError, match="do not sum"):
        reconstruct_file(manifest_path, nodes, tmp_path / "out.bin", request_fn=fake)


def test_m5_replicates_each_chunk_to_distinct_workers(tmp_path):
    nodes = make_nodes(tmp_path, 3)
    source = tmp_path / "replicated.bin"
    source.write_bytes(b"replicate-me-" * 10)
    manifest_path = tmp_path / "replicated.manifest.json"
    fake = FakeTLS()
    manifest = distribute_file(source, nodes, manifest_path, chunk_size=12, request_fn=fake, replicas=2)
    configured_nodes = __import__("quantum_shield.distribution", fromlist=["load_nodes"]).load_nodes(nodes)
    host_by_id = {node["id"]: node["host"] for node in configured_nodes}
    for shard in manifest["shards"]:
        assert len(shard["replicas"]) == 2
        assert len({r["node_id"] for r in shard["replicas"]}) == 2
        for replica in shard["replicas"]:
            assert (host_by_id[replica["node_id"]], shard["shard_id"]) in fake.data
    restored = tmp_path / "replicated-restored.bin"
    reconstruct_file(manifest_path, nodes, restored, request_fn=fake)
    assert restored.read_bytes() == source.read_bytes()


def test_m5_reconstructs_from_replica_when_primary_is_unavailable(tmp_path):
    nodes = make_nodes(tmp_path, 2)
    source = tmp_path / "source.bin"
    source.write_bytes(b"failover works" * 5)
    manifest_path = tmp_path / "manifest.json"
    fake = FakeTLS()
    manifest = distribute_file(source, nodes, manifest_path, chunk_size=10, request_fn=fake, replicas=2)
    primary_ids = {shard["replicas"][0]["node_id"] for shard in manifest["shards"]}
    # Fail one primary worker; every chunk still has a copy on the other worker.
    primary_node = next(n for n in __import__("quantum_shield.distribution", fromlist=["load_nodes"]).load_nodes(nodes) if n["id"] in primary_ids)
    fake.fail_get_hosts.add(primary_node["host"])
    restored = tmp_path / "restored.bin"
    reconstruct_file(manifest_path, nodes, restored, request_fn=fake)
    assert restored.read_bytes() == source.read_bytes()


def test_m5_requires_enough_distinct_workers_for_replication(tmp_path):
    nodes = make_nodes(tmp_path, 2)
    source = tmp_path / "source.bin"
    source.write_bytes(b"not enough live nodes")
    manifest_path = tmp_path / "manifest.json"
    fake = FakeTLS()
    fake.fail_store_hosts.add("worker-1.test")
    with pytest.raises(DistributionError, match="could not store chunk"):
        distribute_file(source, nodes, manifest_path, chunk_size=4, request_fn=fake, replicas=2)
    assert not manifest_path.exists()


def test_m5_rejects_replica_count_greater_than_worker_count(tmp_path):
    nodes = make_nodes(tmp_path, 2)
    source = tmp_path / "source.bin"
    source.write_bytes(b"test")
    with pytest.raises(DistributionError, match="replicas must be between"):
        distribute_file(source, nodes, tmp_path / "manifest.json", replicas=3, request_fn=FakeTLS())
