from __future__ import annotations

from pathlib import Path

import pytest

from mineguard.source_keys import SourceKeyConflictError, SourceKeyStore


def test_source_keys_are_immutable_and_not_path_addressable(
    tmp_path: Path,
) -> None:
    store = SourceKeyStore(tmp_path / "keys")
    assert store.put("../../矿井/来源", b"a" * 32)
    assert not store.put("../../矿井/来源", b"a" * 32)
    assert store.get("../../矿井/来源") == b"a" * 32
    assert len(list((tmp_path / "keys").glob("*.key"))) == 1
    assert not (tmp_path / "矿井").exists()

    with pytest.raises(SourceKeyConflictError):
        store.put("../../矿井/来源", b"b" * 32)


def test_source_key_validates_inputs(tmp_path: Path) -> None:
    store = SourceKeyStore(tmp_path / "keys")
    with pytest.raises(ValueError):
        store.put("", b"a" * 32)
    with pytest.raises(ValueError):
        store.put("source", b"short")
    assert store.get("missing") is None

    assert store.put_system("evidence", b"e" * 32)
    assert not store.put_system("evidence", b"e" * 32)
    assert store.get_system("evidence") == b"e" * 32
    with pytest.raises(SourceKeyConflictError):
        store.put_system("evidence", b"x" * 32)
