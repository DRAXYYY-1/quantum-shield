import base64
import json
from pathlib import Path

from quantum_shield import file_cli


def test_send_encrypts_payload_before_distribution(tmp_path, monkeypatch, capsys):
    source = tmp_path / "hello.txt"
    source.write_bytes(b"plaintext must not reach storage")
    nodes = Path(__file__).resolve().parents[1] / "nodes.json"
    manifest = tmp_path / "hello.manifest.json"
    answers = iter([source, nodes, manifest])
    monkeypatch.setattr(file_cli, "_ask_path", lambda *_args, **_kwargs: Path(next(answers)))
    monkeypatch.setattr(file_cli, "_ask_int", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(file_cli, "load_or_create_identity", lambda: ("public-key", "private-key"))
    monkeypatch.setattr(file_cli, "encrypt_for_recipient", lambda data, _key, file_id: {
        "file_id": file_id, "ciphertext_b64": base64.b64encode(data[::-1]).decode("ascii")
    })
    monkeypatch.setattr(file_cli, "envelope_to_json", lambda envelope: json.dumps(envelope))

    captured = {}

    def fake_distribute(input_path, _nodes_path, manifest_path, _chunk_size, replicas):
        payload = Path(input_path).read_bytes()
        assert b"plaintext must not reach storage" not in payload
        assert b'"ciphertext_b64"' in payload
        captured["replicas"] = replicas
        captured["manifest_path"] = Path(manifest_path)
        return {"file_id": "a" * 32, "shard_count": 1}

    monkeypatch.setattr(file_cli, "distribute_file", fake_distribute)
    file_cli._send()
    assert captured["replicas"] == 1
    assert captured["manifest_path"] == manifest
    assert "SEND COMPLETE" in capsys.readouterr().out


def test_retrieve_decrypts_only_after_reconstruction(tmp_path, monkeypatch, capsys):
    nodes = Path(__file__).resolve().parents[1] / "nodes.json"
    manifest = tmp_path / "file.manifest.json"
    manifest.write_text("test manifest")
    output = tmp_path / "restored.txt"
    answers = iter([manifest, nodes, output])
    monkeypatch.setattr(file_cli, "_ask_path", lambda *_args, **_kwargs: Path(next(answers)))
    monkeypatch.setattr(file_cli, "load_or_create_identity", lambda: ("public-key", "private-key"))
    monkeypatch.setattr(file_cli, "envelope_from_json", lambda raw: {
        "file_id": "crypto-file-id", "encoded": raw
    })
    monkeypatch.setattr(file_cli, "decrypt_for_recipient", lambda envelope, key, file_id: (
        b"restored original bytes" if key == "private-key" and file_id == "crypto-file-id" else b"bad"
    ))

    def fake_reconstruct(_manifest, _nodes, output_path):
        Path(output_path).write_text('{"encrypted":true}', encoding="utf-8")
        return Path(output_path)

    monkeypatch.setattr(file_cli, "reconstruct_file", fake_reconstruct)
    file_cli._retrieve()
    assert output.read_bytes() == b"restored original bytes"
    assert "RETRIEVE COMPLETE" in capsys.readouterr().out
