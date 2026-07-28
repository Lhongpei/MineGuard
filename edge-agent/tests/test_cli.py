from __future__ import annotations

import json

from mine_edge.cli import main


def test_sources_command_validates_and_prints_safe_configuration(
    monkeypatch, tmp_path, capsys
) -> None:
    monkeypatch.setenv(
        "MINE_EDGE_SOURCES_JSON",
        json.dumps(
            [
                {
                    "source_id": "source-api",
                    "adapter": "http-poll",
                    "url": "https://source.example/readings?secret=hidden",
                    "interval_seconds": 10,
                    "timeout_seconds": 3,
                    "missing_after_seconds": 60,
                    "token_env": "SOURCE_API_TOKEN",
                }
            ]
        ),
    )
    monkeypatch.setenv("SOURCE_API_TOKEN", "never-print-this-value")
    code = main(["--db", str(tmp_path / "edge.db"), "sources"])
    output = capsys.readouterr().out
    body = json.loads(output)
    assert code == 0
    assert body["count"] == 1
    assert body["items"][0]["location"] == "https://source.example/readings"
    assert body["items"][0]["query_configured"] is True
    assert "never-print-this-value" not in output
    assert "secret=hidden" not in output
