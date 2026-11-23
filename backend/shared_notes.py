"""Dedicated low-risk note storage for explicitly permitted OAuth clients.

This folder is NOT the backend workspace. Only flat UTF-8 .md/.txt files
with short ASCII names are accepted. No shell, SSH, arbitrary paths, or
symlink targets are exposed through these tools.
"""
from __future__ import annotations

import os
import re
import stat
import tempfile
from pathlib import Path

MAX_NOTE_BYTES = 32 * 1024
MAX_LIST_ENTRIES = 200
_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.(?:md|txt)$", re.ASCII | re.IGNORECASE)
_RESERVED_WIN = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def default_notes_dir() -> Path:
    from app.paths import user_data_dir
    return user_data_dir() / "shared_notes"


def check_note_name(name: str) -> str:
    if not isinstance(name, str) or not _FILENAME.fullmatch(name) or ".." in name:
        raise ValueError("Only flat ASCII .md and .txt note names are allowed")
    if name.split(".", 1)[0].upper() in _RESERVED_WIN:
        raise ValueError("Windows reserved device names are not allowed")
    return name


class SharedNotes:
    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory).expanduser().absolute()
        if self.directory.is_symlink():
            raise ValueError("Shared notes directory must not be a symlink")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.directory.is_symlink():
            raise ValueError("Shared notes directory must not be a symlink")
        self.directory = self.directory.resolve()
        if os.name != "nt":
            self.directory.chmod(0o700)

    def _path(self, name: str) -> Path:
        name = check_note_name(name)
        target = self.directory / name
        # Recheck each time; reject symlinks (even those pointing within root).
        if target.is_symlink() or target.resolve().parent != self.directory:
            raise ValueError("Symlink or path outside shared notes directory")
        return target

    def list_names(self) -> list[str]:
        out = []
        for item in sorted(self.directory.iterdir(), key=lambda p: p.name.casefold()):
            if len(out) >= MAX_LIST_ENTRIES:
                break
            try:
                self._path(item.name)
            except ValueError:
                continue
            if item.is_file() and not item.is_symlink():
                out.append(item.name)
        return out

    def read(self, name: str) -> str:
        target = self._path(name)
        if not target.is_file():
            raise FileNotFoundError("Note not found")
        # O_NOFOLLOW prevents an attacker with local write access from
        # swapping a symlink between the check and open on POSIX systems.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, flags)
        with os.fdopen(fd, "rb") as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_NOTE_BYTES:
                raise ValueError("Note too large or not a regular file")
            data = file.read(MAX_NOTE_BYTES + 1)
        if len(data) > MAX_NOTE_BYTES:
            raise ValueError("Note too large")
        return data.decode("utf-8", errors="strict")

    def write(self, name: str, content: str) -> None:
        target = self._path(name)
        if not isinstance(content, str):
            raise ValueError("Note content must be text")
        data = content.encode("utf-8")
        if len(data) > MAX_NOTE_BYTES:
            raise ValueError("Note exceeds the size limit")
        # Temporary write + replace: never follow an existing symlink as a
        # destination, and never leave a partly written note after a crash.
        tmp_name = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.directory, prefix=".write-", suffix=".tmp",
                delete=False,
            ) as file:
                tmp_name = file.name
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
            if os.name != "nt":
                os.chmod(tmp_name, 0o600)
            self._path(name)
            os.replace(tmp_name, target)
        finally:
            if tmp_name and os.path.exists(tmp_name):
                os.unlink(tmp_name)
