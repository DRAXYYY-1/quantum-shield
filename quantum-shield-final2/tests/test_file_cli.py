from pathlib import Path

from quantum_shield.distribution import load_nodes
from quantum_shield.file_cli import main


def test_nodes_json_starter_has_two_configured_node_entries():
    project_root = Path(__file__).resolve().parents[1]
    nodes = load_nodes(project_root / "nodes.json")
    assert [node["id"] for node in nodes] == ["worker-a", "worker-b"]
    # The sample uses documentation-only IPs; users must replace them for a real lab.
    assert all(node["host"].startswith("192.0.2.") for node in nodes)


def test_interactive_menu_can_exit(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _prompt: "3")
    assert main() == 0
    output = capsys.readouterr().out
    assert "1) Send a file" in output
    assert "2) Retrieve a file" in output
    assert "Goodbye." in output
