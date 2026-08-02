from __future__ import annotations

from pathlib import Path

import pytest

from mineguard.instance_lock import (
    InstanceAlreadyRunningError,
    LOCK_FILENAME,
    StateInstanceLock,
)


def test_state_instance_lock_rejects_a_second_platform_process(
    tmp_path: Path,
) -> None:
    first = StateInstanceLock(tmp_path).acquire()
    try:
        with pytest.raises(InstanceAlreadyRunningError, match="已有"):
            StateInstanceLock(tmp_path).acquire()
    finally:
        first.close()

    with StateInstanceLock(tmp_path):
        assert (tmp_path / LOCK_FILENAME).is_file()


def test_state_instance_lock_is_idempotent_and_rejects_a_symlink(
    tmp_path: Path,
) -> None:
    lock = StateInstanceLock(tmp_path)
    assert lock.acquire() is lock
    assert lock.acquire() is lock
    lock.close()
    lock.close()

    path = tmp_path / LOCK_FILENAME
    path.unlink()
    target = tmp_path / "unexpected-target"
    target.write_bytes(b"x")
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("the current test account cannot create symbolic links")
    with pytest.raises(OSError, match="符号链接"):
        StateInstanceLock(tmp_path).acquire()
