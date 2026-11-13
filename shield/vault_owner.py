"""Exclusive service ownership across local processes; lock files are never unlinked."""

import os
import stat
from pathlib import Path


class VaultOwnership:
    def __init__(self, path: Path):
        self._fd: int | None = None
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(
            str(path) + ".lock",
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("vault lock must be a regular file")
            if os.name == "posix":
                import fcntl

                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif os.name == "nt":
                import msvcrt

                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                raise OSError("vault ownership locking unavailable")
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
