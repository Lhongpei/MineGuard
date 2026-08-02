"""Cross-platform single-instance lock for one MineGuard state directory."""

from __future__ import annotations

import os
from pathlib import Path
from types import TracebackType


LOCK_FILENAME = ".mineguard-platform.instance.lock"


class InstanceAlreadyRunningError(OSError):
    """Another Platform process already owns the selected state directory."""


class StateInstanceLock:
    """Hold an advisory OS lock for the lifetime of a Platform server.

    The stable lock file is deliberately not unlinked on release.  Deleting a
    lock file after closing it introduces a race in which a new process can
    lock the old inode/handle while a third process creates and locks a new
    file under the same name.
    """

    def __init__(self, state_directory: str | os.PathLike[str]) -> None:
        root = Path(state_directory).resolve()
        self.path = root / LOCK_FILENAME
        self._descriptor: int | None = None

    def acquire(self) -> "StateInstanceLock":
        if self._descriptor is not None:
            return self
        if self.path.is_symlink():
            raise OSError(f"状态锁文件不能是符号链接：{self.path}")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            if os.fstat(descriptor).st_size < 1:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise InstanceAlreadyRunningError(
                    f"同一状态目录已有 MineGuard Platform 实例运行：{self.path.parent}"
                ) from error
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
            self._descriptor = descriptor
            return self
        except BaseException:
            os.close(descriptor)
            raise

    def close(self) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            return
        self._descriptor = None
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def __enter__(self) -> "StateInstanceLock":
        return self.acquire()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


__all__ = [
    "InstanceAlreadyRunningError",
    "LOCK_FILENAME",
    "StateInstanceLock",
]
