"""Cross-platform exclusive lock for one process per Agent state database."""

from __future__ import annotations

import os
from contextlib import AbstractContextManager, nullcontext, suppress
from pathlib import Path
from types import TracebackType


class InstanceLock(AbstractContextManager["InstanceLock"]):
    def __init__(self, database_path: str | Path):
        if str(database_path) == ":memory:":
            raise ValueError("服务模式不能使用内存数据库")
        database = Path(database_path).expanduser().resolve()
        self.path = Path(f"{database}.instance.lock")
        self._stream = None

    def __enter__(self) -> InstanceLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        stream = self.path.open("a+b")
        try:
            stream.seek(0, os.SEEK_END)
            if stream.tell() == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as error:
            stream.close()
            raise ValueError(
                "该状态库已有企业 Agent 进程运行；一矿一实例不能重复启动，"
                "恢复操作也必须先停止服务"
            ) from error
        self._stream = stream
        with suppress(OSError):
            os.chmod(self.path, 0o600)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        stream = self._stream
        self._stream = None
        if stream is None:
            return
        try:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        finally:
            stream.close()


def lock_for_database(
    database_path: str | Path,
) -> AbstractContextManager[object]:
    if str(database_path) == ":memory:":
        return nullcontext()
    return InstanceLock(database_path)
