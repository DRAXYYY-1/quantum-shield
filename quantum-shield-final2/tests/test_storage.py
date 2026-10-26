import hashlib
import io
import socket
import threading
from pathlib import Path

import pytest

from quantum_shield.storage.worker import (
    ProtocolError, ShardStore, StorageError, handle_client, recv_exact, send_frame, recv_header,
)


def test_put_get_round_trip(tmp_path):
    store = ShardStore(tmp_path / "store")
    payload = bytes(range(256)) * 100
    result = store.put_bytes("sample-1", payload)
    assert result.size == len(payload)
    assert result.sha256 == hashlib.sha256(payload).hexdigest()
    assert store.get_bytes("sample-1") == payload


def test_payload_larger_than_4k(tmp_path):
    store = ShardStore(tmp_path / "store")
    payload = b"Q" * 100_000
    store.put_bytes("large", payload)
    assert store.get_bytes("large") == payload


def test_reject_path_traversal(tmp_path):
    store = ShardStore(tmp_path / "store")
    for bad in ("../escape", "/tmp/x", "..", "a/b", "a\\\\b"):
        with pytest.raises(StorageError):
            store.put_bytes(bad, b"no")


def test_reject_oversized_shard(tmp_path):
    store = ShardStore(tmp_path / "store", max_shard_bytes=10)
    with pytest.raises(StorageError):
        store.put_bytes("too-big", b"x" * 11)


def test_bad_hash_does_not_commit_file(tmp_path):
    store = ShardStore(tmp_path / "store")
    with pytest.raises(StorageError, match="SHA-256"):
        store.put_bytes("bad-hash", b"payload", "0" * 64)
    assert not (tmp_path / "store" / "bad-hash.shard").exists()
    assert list((tmp_path / "store").glob(".incoming-*")) == []


def test_truncated_stream_does_not_commit_file(tmp_path):
    store = ShardStore(tmp_path / "store")
    with pytest.raises(StorageError, match="ended before"):
        store.put_stream("short", 20, hashlib.sha256(b"x" * 20).hexdigest(), io.BytesIO(b"short"))
    assert not (tmp_path / "store" / "short.shard").exists()


def test_framed_protocol_handles_partial_reads():
    left, right = socket.socketpair()
    try:
        def writer():
            send_frame(left, {"version": 1, "op": "GET", "shard_id": "abc"})
        thread = threading.Thread(target=writer)
        thread.start()
        header = recv_header(right)
        thread.join()
        assert header["op"] == "GET"
        assert header["shard_id"] == "abc"
    finally:
        left.close()
        right.close()


def test_worker_store_get_protocol(tmp_path):
    store = ShardStore(tmp_path / "store")
    client, server = socket.socketpair()
    payload = b"encrypted-shard" * 1000

    def serve_once():
        with server:
            handle_client(server, store)

    thread = threading.Thread(target=serve_once)
    thread.start()
    send_frame(client, {
        "version": 1, "op": "STORE", "shard_id": "integration-1",
        "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()
    }, payload)
    response = recv_header(client)
    assert response["ok"] is True
    client.close()
    thread.join(timeout=2)
    assert store.get_bytes("integration-1") == payload
