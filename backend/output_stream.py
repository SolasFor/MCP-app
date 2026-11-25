"""Bounded streaming output buffers, disk spool quotas, pagination, and safe decoding."""
from __future__ import annotations

import shutil
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from app.core.redaction import SecretRedactor
from app.platform import get_platform

DEFAULT_MAX_MEMORY_BYTES = 64 * 1024
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 20 * 1024 * 1024
DEFAULT_MAX_FILES = 100
DEFAULT_TTL_SECONDS = 3600


def decode_process_bytes(data: bytes, encoding_hint: str | None = None) -> str:
    """Decode subprocess bytes cleanly for UTF-8 and Windows OEM/ANSI codepages."""
    if not data:
        return ""
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        pass

    candidates: list[str] = []
    if encoding_hint:
        candidates.append(encoding_hint)
    if sys.platform == "win32":
        platform = get_platform()
        candidates.append(platform.default_oem_encoding())
        candidates.append(platform.default_ansi_encoding())

    seen: set[str] = {"utf-8"}
    for enc in candidates:
        norm = enc.lower()
        if norm in seen:
            continue
        seen.add(norm)
        try:
            return data.decode(enc, errors="strict")
        except (UnicodeDecodeError, LookupError):
            continue

    return data.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class OutputPage:
    """Paginated slice of captured process output."""

    run_id: str
    stream: Literal["stdout", "stderr"]
    text: str
    offset: int
    limit: int
    total_bytes: int
    returned_bytes: int
    has_more: bool
    next_offset: int
    truncated_by_quota: bool


class SpoolWriter:
    """Bounded per-run disk spool for stdout and stderr."""

    def __init__(self, manager: OutputSpoolManager, run_id: str, run_dir: Path) -> None:
        self._manager = manager
        self.run_id = run_id
        self.run_dir = run_dir
        self._lock = threading.Lock()
        self.written_bytes: dict[str, int] = {"stdout": 0, "stderr": 0}
        self.dropped_bytes: dict[str, int] = {"stdout": 0, "stderr": 0}

    def write(self, stream: Literal["stdout", "stderr"], chunk: bytes) -> None:
        if not chunk:
            return
        with self._lock:
            current = self.written_bytes[stream]
            remaining = max(0, self._manager.max_file_bytes - current)
            if remaining <= 0:
                self.dropped_bytes[stream] += len(chunk)
                return
            to_write = chunk[:remaining]
            dropped = len(chunk) - len(to_write)
            if dropped > 0:
                self.dropped_bytes[stream] += dropped
            target = self.run_dir / f"{stream}.bin"
            with target.open("ab") as fh:
                fh.write(to_write)
            self.written_bytes[stream] = current + len(to_write)
            self._manager.record_written(len(to_write), exclude_run_id=self.run_id)


class OutputSpoolManager:
    """Disk-bounded spool directory with LRU/TTL rotation and paginated reads."""

    def __init__(
        self,
        spool_dir: Path,
        *,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_files: int = DEFAULT_MAX_FILES,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self.spool_dir = Path(spool_dir)
        self.max_total_bytes = max(1024, int(max_total_bytes))
        self.max_file_bytes = max(512, int(max_file_bytes))
        self.max_files = max(1, int(max_files))
        self.ttl_seconds = max(1, int(ttl_seconds))
        self._lock = threading.RLock()
        self._platform = get_platform()
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self._platform.restrict_path_acl(self.spool_dir, is_dir=True)

    def create_spool(self, run_id: str) -> SpoolWriter:
        clean_id = "".join(ch for ch in run_id if ch.isalnum() or ch in ("-", "_"))[:64] or "run"
        with self._lock:
            self.enforce_quotas(exclude_run_id=clean_id)
            run_dir = self.spool_dir / clean_id
            run_dir.mkdir(parents=True, exist_ok=True)
            self._platform.restrict_path_acl(run_dir, is_dir=True)
            return SpoolWriter(self, clean_id, run_dir)

    def record_written(self, _added_bytes: int, *, exclude_run_id: str | None = None) -> None:
        with self._lock:
            self.enforce_quotas(exclude_run_id=exclude_run_id)

    def total_usage_bytes(self) -> int:
        if not self.spool_dir.exists():
            return 0
        total = 0
        for item in self.spool_dir.rglob("*"):
            if item.is_file():
                try:
                    total += item.stat().st_size
                except OSError:
                    pass
        return total

    def _run_dirs(self) -> list[tuple[float, int, Path]]:
        if not self.spool_dir.exists():
            return []
        entries: list[tuple[float, int, Path]] = []
        for child in self.spool_dir.iterdir():
            if not child.is_dir():
                continue
            try:
                mtime = child.stat().st_mtime
            except OSError:
                mtime = 0.0
            size = 0
            for f in child.iterdir():
                if f.is_file():
                    try:
                        size += f.stat().st_size
                        mtime = max(mtime, f.stat().st_mtime)
                    except OSError:
                        pass
            entries.append((mtime, size, child))
        entries.sort(key=lambda item: item[0])  # oldest first
        return entries

    def enforce_quotas(self, *, exclude_run_id: str | None = None) -> int:
        """Delete expired or oldest spools until within disk and file-count quotas."""
        removed = 0
        now = time.time()
        with self._lock:
            entries = self._run_dirs()
            remaining: list[tuple[float, int, Path]] = []
            for mtime, size, path in entries:
                if path.name != exclude_run_id and (now - mtime) > self.ttl_seconds:
                    shutil.rmtree(path, ignore_errors=True)
                    removed += 1
                else:
                    remaining.append((mtime, size, path))

            total_size = sum(item[1] for item in remaining)
            while remaining and (total_size > self.max_total_bytes or len(remaining) > self.max_files):
                idx = 0
                if exclude_run_id and remaining[0][2].name == exclude_run_id:
                    if len(remaining) == 1:
                        break
                    idx = 1
                _mtime, size, victim = remaining.pop(idx)
                shutil.rmtree(victim, ignore_errors=True)
                total_size = max(0, total_size - size)
                removed += 1
        return removed

    def cleanup_expired(self) -> int:
        return self.enforce_quotas()

    def cleanup_all(self) -> int:
        removed = 0
        with self._lock:
            for _mtime, _size, path in self._run_dirs():
                shutil.rmtree(path, ignore_errors=True)
                removed += 1
        return removed

    def read_page(
        self,
        run_id: str,
        stream: Literal["stdout", "stderr"] = "stdout",
        *,
        offset: int = 0,
        limit: int = 8000,
        redactor: SecretRedactor | None = None,
    ) -> OutputPage:
        clean_id = "".join(ch for ch in run_id if ch.isalnum() or ch in ("-", "_"))[:64]
        target = self.spool_dir / clean_id / f"{stream}.bin"
        safe_offset = max(0, int(offset))
        safe_limit = max(1, min(int(limit), 65536))
        if not target.is_file():
            return OutputPage(
                run_id=clean_id,
                stream=stream,
                text="",
                offset=safe_offset,
                limit=safe_limit,
                total_bytes=0,
                returned_bytes=0,
                has_more=False,
                next_offset=safe_offset,
                truncated_by_quota=False,
            )
        total = target.stat().st_size
        with target.open("rb") as fh:
            fh.seek(min(safe_offset, total))
            chunk = fh.read(safe_limit)
        text = decode_process_bytes(chunk)
        if redactor is not None:
            text = redactor.redact_text(text)
        returned = len(chunk)
        next_off = min(total, safe_offset + returned)
        return OutputPage(
            run_id=clean_id,
            stream=stream,
            text=text,
            offset=safe_offset,
            limit=safe_limit,
            total_bytes=total,
            returned_bytes=returned,
            has_more=next_off < total,
            next_offset=next_off,
            truncated_by_quota=total >= self.max_file_bytes,
        )


class BoundedOutputBuffer:
    """In-memory head+tail ring buffer backed by optional disk spool."""

    def __init__(
        self,
        *,
        max_memory_bytes: int = DEFAULT_MAX_MEMORY_BYTES,
        spool: SpoolWriter | None = None,
        stream_name: Literal["stdout", "stderr"] = "stdout",
    ) -> None:
        self.max_memory_bytes = max(1024, int(max_memory_bytes))
        self._head_limit = self.max_memory_bytes // 2
        self._tail_limit = self.max_memory_bytes - self._head_limit
        self._head = bytearray()
        self._tail = bytearray()
        self._spool = spool
        self._stream_name: Literal["stdout", "stderr"] = stream_name
        self._lock = threading.RLock()
        self.total_bytes = 0
        self.dropped_memory_bytes = 0

    @property
    def memory_bytes_used(self) -> int:
        with self._lock:
            return len(self._head) + len(self._tail)

    def append(self, chunk: bytes) -> None:
        if not chunk:
            return
        with self._lock:
            self.total_bytes += len(chunk)
            if self._spool is not None:
                self._spool.write(self._stream_name, chunk)

            view = memoryview(chunk)
            if len(self._head) < self._head_limit:
                take = min(len(view), self._head_limit - len(self._head))
                self._head.extend(view[:take])
                view = view[take:]

            if len(view) == 0:
                return

            if len(view) >= self._tail_limit:
                self.dropped_memory_bytes += len(self._tail) + (len(view) - self._tail_limit)
                self._tail = bytearray(view[-self._tail_limit:])
                return

            combined_len = len(self._tail) + len(view)
            if combined_len > self._tail_limit:
                evict = combined_len - self._tail_limit
                self.dropped_memory_bytes += evict
                del self._tail[:evict]
            self._tail.extend(view)

    def render(
        self,
        *,
        limit: int = 8000,
        offset: int = 0,
        redactor: SecretRedactor | None = None,
        spool_manager: OutputSpoolManager | None = None,
    ) -> str:
        safe_offset = max(0, int(offset))
        safe_limit = max(1, int(limit))

        with self._lock:
            spool_run_id = self._spool.run_id if self._spool is not None else None
            if safe_offset > 0 and spool_run_id is not None and spool_manager is not None:
                page = spool_manager.read_page(
                    spool_run_id,
                    self._stream_name,
                    offset=safe_offset,
                    limit=safe_limit,
                    redactor=redactor,
                )
                return page.text

            head_text = decode_process_bytes(bytes(self._head))
            tail_text = decode_process_bytes(bytes(self._tail))
            dropped = self.dropped_memory_bytes

        if dropped > 0:
            marker = f"\n\n... [ВЫВОД ОБРЕЗАН: пропущено {dropped} байт] ...\n\n"
            text = head_text + marker + tail_text
        else:
            text = head_text + tail_text

        if redactor is not None:
            text = redactor.redact_text(text)

        if safe_offset > 0:
            text = text[safe_offset:]

        if len(text) <= safe_limit:
            return text
        if safe_offset > 0:
            return text[:safe_limit]
        half = safe_limit // 2
        omitted = len(text) - safe_limit
        return f"{text[:half]}\n\n... [ВЫВОД ОБРЕЗАН: пропущено {omitted} симв.] ...\n\n{text[-half:]}"


async def drain_stream_to_buffer(
    stream, buffer: BoundedOutputBuffer, chunk_size: int = 16384
) -> None:
    """Drain an async subprocess StreamReader concurrently into a bounded buffer."""
    if stream is None:
        return
    while True:
        chunk = await stream.read(chunk_size)
        if not chunk:
            break
        buffer.append(chunk)
