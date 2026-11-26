"""Centralized, thread- and multi-process-safe persistent logging for MCP-app.

Directory layout under ``%APPDATA%\\MCPApp\\logs\\`` (or ``$MCP_LOGS_DIR``):
    app.log, backend.log, tunnel.log, oauth.log, proxy.log, computer_use.log,
    gateway.log, tasks.log, servers.log, workspaces.log, extensions.log,
    ssh.log, automation.log, errors.log, crash.log, archive/

Security & operational guarantees:
- Starts immediately on app/backend launch (before GUI initialization).
- All secrets are scrubbed BEFORE disk writes, UI rendering, or export — even at DEBUG level.
- Protected security audit files (``mcp_execution_audit.jsonl``, ``desktop_policy_audit.jsonl``)
  are stored separately and NEVER deleted during normal rotation or GUI log clearing.
- Cross-process file lock serializes batch appends and gzip rotation, closing file handles
  before releasing the lock to avoid Windows file-lock contention (WinError 32).
- Asynchronous background writer keeps GUI non-blocking; synchronous flush/crash writes
  ensure crash tracebacks are persisted even under abnormal exit.
"""
from __future__ import annotations

import atexit
import gzip
import io
import logging
import os
import queue
import shutil
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from app.core.redaction import SecretRedactor
from app.paths import user_data_dir

LOG_COMPONENTS: tuple[str, ...] = (
    "app",
    "backend",
    "tunnel",
    "oauth",
    "proxy",
    "computer_use",
    "gateway",
    "tasks",
    "servers",
    "workspaces",
    "extensions",
    "ssh",
    "automation",
    "errors",
    "crash",
)

LOG_LEVELS: tuple[str, ...] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
LEVEL_RANK: dict[str, int] = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}

DEFAULT_MAX_FILE_MB = 10
DEFAULT_RETENTION_DAYS = 30
DEFAULT_MAX_TOTAL_MB = 200
DEFAULT_LEVEL = "INFO"

_PROTECTED_AUDIT_NAMES = frozenset({
    "mcp_execution_audit.jsonl",
    "desktop_policy_audit.jsonl",
})

_LEVEL_MAP_STD = {
    logging.DEBUG: "DEBUG",
    logging.INFO: "INFO",
    logging.WARNING: "WARNING",
    logging.ERROR: "ERROR",
    logging.CRITICAL: "CRITICAL",
}


def default_logs_dir() -> Path:
    """Return active log directory (honors ``MCP_LOGS_DIR`` for child processes and tests)."""
    env_dir = os.environ.get("MCP_LOGS_DIR", "").strip()
    if env_dir:
        return Path(env_dir).expanduser()
    return user_data_dir() / "logs"


def normalize_component(component: str) -> str:
    clean = (component or "app").strip().lower()
    if clean == "server":
        return "backend"
    if clean in LOG_COMPONENTS:
        return clean
    return "app"


def normalize_level(level: str) -> str:
    upper = (level or DEFAULT_LEVEL).strip().upper()
    if upper in ("WARN",):
        return "WARNING"
    if upper in ("ERR",):
        return "ERROR"
    return upper if upper in LEVEL_RANK else DEFAULT_LEVEL


def format_timestamp(ts: float | None = None) -> str:
    dt = datetime.fromtimestamp(ts if ts is not None else time.time(), tz=timezone.utc).astimezone()
    return dt.isoformat(timespec="milliseconds")


@dataclass
class LogConfig:
    enabled: bool = True
    level: str = DEFAULT_LEVEL
    max_file_mb: int = DEFAULT_MAX_FILE_MB
    retention_days: int = DEFAULT_RETENTION_DAYS
    max_total_mb: int = DEFAULT_MAX_TOTAL_MB
    auto_rotate: bool = True
    archive_enabled: bool = True

    def sanitized(self) -> "LogConfig":
        level = normalize_level(self.level)
        max_file_mb = max(1, min(int(self.max_file_mb), 512))
        retention_days = max(1, min(int(self.retention_days), 3650))
        max_total_mb = max(max_file_mb, min(int(self.max_total_mb), 10240))
        return LogConfig(
            enabled=bool(self.enabled),
            level=level,
            max_file_mb=max_file_mb,
            retention_days=retention_days,
            max_total_mb=max_total_mb,
            auto_rotate=bool(self.auto_rotate),
            archive_enabled=bool(self.archive_enabled),
        )


@dataclass(frozen=True)
class LogRecordEntry:
    timestamp: str
    level: str
    component: str
    pid: int
    request_id: str
    event_code: str
    message: str

    def format_line(self) -> str:
        safe_msg = self.message.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " | ")
        req = (self.request_id or "-").strip() or "-"
        ev = (self.event_code or "event").strip() or "event"
        return (
            f"{self.timestamp} | {self.level:<8s} | {self.component:<12s} | "
            f"pid={self.pid} | req={req} | event={ev} | {safe_msg}"
        )


def parse_log_line(line: str, fallback_component: str = "app") -> dict[str, str]:
    """Parse structured log line or legacy line cleanly for UI display and filtering."""
    raw = line.rstrip("\r\n")
    parts = [p.strip() for p in raw.split("|", 6)]
    if len(parts) == 7 and parts[3].startswith("pid="):
        req = parts[4][4:] if parts[4].startswith("req=") else parts[4]
        ev = parts[5][6:] if parts[5].startswith("event=") else parts[5]
        return {
            "timestamp": parts[0],
            "level": normalize_level(parts[1]),
            "component": normalize_component(parts[2]),
            "pid": parts[3][4:],
            "request_id": req,
            "event_code": ev,
            "message": parts[6],
            "raw": raw,
        }
    return {
        "timestamp": "",
        "level": infer_level(raw),
        "component": normalize_component(fallback_component),
        "pid": "",
        "request_id": "-",
        "event_code": "legacy",
        "message": raw,
        "raw": raw,
    }


def infer_level(line: str) -> str:
    upper = line.upper()
    if "CRITICAL" in upper or "TRACEBACK" in upper:
        return "CRITICAL"
    if "✖" in line or "[ERROR]" in upper or " ERR " in upper or "| ERROR" in upper or "ERROR:" in upper:
        return "ERROR"
    if "⚠" in line or "[WARNING]" in upper or " WRN " in upper or "WARN" in upper:
        return "WARNING"
    if "[DEBUG]" in upper or "| DEBUG" in upper:
        return "DEBUG"
    return "INFO"


class ComponentStdHandler(logging.Handler):
    """Bridge Python ``logging`` records from a component into ``LoggingManager``."""

    def __init__(self, manager: "LoggingManager", component: str, *, event_code: str = "py_log") -> None:
        super().__init__(logging.DEBUG)
        self._manager = manager
        self._component = normalize_component(component)
        self._event_code = event_code

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if getattr(record, "_from_mcp_logging_manager", False):
                return
            msg = self.format(record) if self.formatter else record.getMessage()
            level = _LEVEL_MAP_STD.get(record.levelno, "INFO")
            req_id = str(getattr(record, "request_id", "") or "-")
            ev = str(getattr(record, "event_code", "") or self._event_code)
            self._manager.log(self._component, level, msg, event_code=ev, request_id=req_id)
        except Exception:  # noqa: BLE001
            pass


class LoggingManager:
    """Centralized persistent logger with bounded async queue, safe MP lock, rotation, and redaction."""

    def __init__(
        self,
        base_dir: Path | None = None,
        *,
        config: LogConfig | None = None,
        redactor: SecretRedactor | None = None,
        auto_start: bool = True,
    ) -> None:
        self._base_dir = Path(base_dir).expanduser() if base_dir is not None else default_logs_dir()
        self._archive_dir = self._base_dir / "archive"
        self._lock_path = self._base_dir / ".write.lock"
        self._config = (config or LogConfig()).sanitized()
        self._redactor = redactor or SecretRedactor()
        self._thread_lock = threading.RLock()
        self._queue: queue.Queue[tuple[LogRecordEntry, bool] | threading.Event | None] = queue.Queue(maxsize=10000)
        self._worker: threading.Thread | None = None
        self._started = False
        self._shutting_down = False
        self.last_io_error: str = ""
        self._last_io_error_ts = 0.0
        self._write_failures = 0

        if auto_start:
            self.initialize()

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    @property
    def archive_dir(self) -> Path:
        return self._archive_dir

    @property
    def config(self) -> LogConfig:
        with self._thread_lock:
            return self._config

    @property
    def redactor(self) -> SecretRedactor:
        return self._redactor

    def component_path(self, component: str) -> Path:
        return self._base_dir / f"{normalize_component(component)}.log"

    def set_base_dir(self, base_dir: Path) -> None:
        """Re-point logs directory (flushes pending records first)."""
        self.flush(timeout=2.0)
        with self._thread_lock:
            self._base_dir = Path(base_dir).expanduser()
            self._archive_dir = self._base_dir / "archive"
            self._lock_path = self._base_dir / ".write.lock"
            self._ensure_dirs()
            self._ensure_component_files()

    def update_config(self, config: LogConfig) -> None:
        with self._thread_lock:
            self._config = config.sanitized()

    def register_secret(self, secret: str) -> None:
        self._redactor.register(secret, allow_short=True)

    def _ensure_dirs(self) -> bool:
        try:
            self._base_dir.mkdir(parents=True, exist_ok=True)
            self._archive_dir.mkdir(parents=True, exist_ok=True)
            return True
        except OSError as exc:
            self._record_io_error(exc)
            return False

    def _ensure_component_files(self) -> None:
        if not self._ensure_dirs():
            return
        with self._process_lock():
            for comp in LOG_COMPONENTS:
                p = self.component_path(comp)
                if not p.exists():
                    try:
                        p.touch(exist_ok=True)
                    except OSError as exc:
                        self._record_io_error(exc)
                        break

    def migrate_legacy_logs(self, data_root: Path | None = None) -> list[str]:
        """Non-destructively copy legacy crash.log / mcp_audit.log history without touching user files."""
        notes: list[str] = []
        root = Path(data_root) if data_root is not None else self._base_dir.parent
        marker = self._base_dir / ".legacy_migrated"
        if marker.exists():
            return notes
        if not self._ensure_dirs():
            return notes

        migrated: list[str] = []
        legacy_crash = root / "crash.log"
        if legacy_crash.is_file() and legacy_crash.stat().st_size > 0:
            try:
                raw = legacy_crash.read_text(encoding="utf-8", errors="replace")
                cleaned = self._redactor.redact_text(raw)
                dest = self._archive_dir / f"legacy_crash_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.log.gz"
                if not dest.exists():
                    with gzip.open(dest, "wt", encoding="utf-8") as gz:
                        gz.write(cleaned)
                    migrated.append("crash.log")
                    notes.append(f"Copied legacy crash.log -> {dest.name}")
            except OSError as exc:
                self._record_io_error(exc)

        legacy_audit = root / "server" / "mcp_audit.log"
        if legacy_audit.is_file() and legacy_audit.stat().st_size > 0:
            # Keep original server/mcp_audit.log intact and preserve snapshot copy in archive.
            try:
                dest = self._archive_dir / f"legacy_mcp_audit_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.log.gz"
                if not dest.exists():
                    raw_lines = legacy_audit.read_text(encoding="utf-8", errors="replace").splitlines()
                    tail = "\n".join(self._redactor.redact_text(line) for line in raw_lines[-2000:])
                    if tail:
                        with gzip.open(dest, "wt", encoding="utf-8") as gz:
                            gz.write(tail + "\n")
                        migrated.append("server/mcp_audit.log")
            except OSError as exc:
                self._record_io_error(exc)

        try:
            marker.write_text(", ".join(migrated) if migrated else "none", encoding="utf-8")
        except OSError as exc:
            self._record_io_error(exc)
        return notes

    def initialize(self, *, data_root: Path | None = None, touch_files: bool = True) -> None:
        with self._thread_lock:
            self._shutting_down = False
            self._ensure_dirs()
            if touch_files:
                self._ensure_component_files()
            self.migrate_legacy_logs(data_root=data_root)
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(
                    target=self._writer_loop,
                    name="mcp-logging-writer",
                    daemon=True,
                )
                self._worker.start()
            self._started = True

    def log(
        self,
        component: str,
        level: str,
        message: str,
        *,
        event_code: str = "event",
        request_id: str = "-",
        timestamp: str | None = None,
        sync: bool = False,
    ) -> bool:
        """Record a log entry after redacting all secrets (even in DEBUG mode)."""
        cfg = self.config
        if not cfg.enabled:
            return False
        norm_level = normalize_level(level)
        if LEVEL_RANK[norm_level] < LEVEL_RANK[cfg.level]:
            return False
        norm_comp = normalize_component(component)
        safe_msg = self._redactor.redact_text(str(message))
        safe_req = self._redactor.redact_text(str(request_id or "-"))[:48]
        safe_event = self._redactor.redact_text(str(event_code or "event"))[:64]
        entry = LogRecordEntry(
            timestamp=timestamp or format_timestamp(),
            level=norm_level,
            component=norm_comp,
            pid=os.getpid(),
            request_id=safe_req,
            event_code=safe_event,
            message=safe_msg,
        )
        if sync or norm_level == "CRITICAL" or self._worker is None or not self._worker.is_alive():
            self._write_batch([(entry, True)])
            return True

        try:
            self._queue.put_nowait((entry, True))
        except queue.Full:
            # Drop oldest item rather than blocking GUI thread if writer is congested.
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait((entry, True))
            except queue.Full:
                return False
        return True

    def debug(
        self, component: str, message: str, *, event_code: str = "debug", request_id: str = "-", sync: bool = False
    ) -> bool:
        return self.log(component, "DEBUG", message, event_code=event_code, request_id=request_id, sync=sync)

    def info(
        self, component: str, message: str, *, event_code: str = "info", request_id: str = "-", sync: bool = False
    ) -> bool:
        return self.log(component, "INFO", message, event_code=event_code, request_id=request_id, sync=sync)

    def warning(
        self, component: str, message: str, *, event_code: str = "warning", request_id: str = "-", sync: bool = False
    ) -> bool:
        return self.log(component, "WARNING", message, event_code=event_code, request_id=request_id, sync=sync)

    def error(
        self, component: str, message: str, *, event_code: str = "error", request_id: str = "-", sync: bool = False
    ) -> bool:
        return self.log(component, "ERROR", message, event_code=event_code, request_id=request_id, sync=sync)

    def critical(
        self, component: str, message: str, *, event_code: str = "critical", request_id: str = "-", sync: bool = True
    ) -> bool:
        return self.log(component, "CRITICAL", message, event_code=event_code, request_id=request_id, sync=sync)

    def log_crash(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: Any,
        *,
        context: str = "unhandled_exception",
    ) -> str:
        """Persist redacted crash traceback synchronously to crash.log and errors.log."""
        raw_tb = "".join(traceback.format_exception(exc_type, exc, tb)) if exc_type is not None else str(exc or "")
        safe_tb = self._redactor.redact_text(raw_tb)
        self.log(
            "crash",
            "CRITICAL",
            f"[{context}] {safe_tb}",
            event_code=context,
            sync=True,
        )
        return safe_tb

    def install_exception_hooks(self, *, chain_previous: bool = False) -> None:
        prev_sys = sys.excepthook
        prev_thread = threading.excepthook

        def _sys_hook(exc_type, exc, tb) -> None:  # noqa: ANN001
            self.log_crash(exc_type, exc, tb, context="sys_excepthook")
            if chain_previous and prev_sys is not sys.__excepthook__:
                try:
                    prev_sys(exc_type, exc, tb)
                except Exception:  # noqa: BLE001
                    pass

        def _thread_hook(args: threading.ExceptHookArgs) -> None:
            tname = getattr(args.thread, "name", "thread")
            self.log_crash(args.exc_type, args.exc_value, args.exc_traceback, context=f"thread:{tname}")
            if chain_previous and prev_thread is not threading.__excepthook__:
                try:
                    prev_thread(args)
                except Exception:  # noqa: BLE001
                    pass

        sys.excepthook = _sys_hook
        threading.excepthook = _thread_hook

    def std_logging_handler(self, component: str, *, event_code: str = "py_log") -> ComponentStdHandler:
        return ComponentStdHandler(self, component, event_code=event_code)

    def flush(self, timeout: float = 3.0) -> bool:
        if self._worker is None or not self._worker.is_alive():
            return True
        ev = threading.Event()
        try:
            self._queue.put(ev, timeout=max(0.1, timeout))
        except queue.Full:
            return False
        return ev.wait(timeout=max(0.1, timeout))

    def shutdown(self, timeout: float = 3.0) -> None:
        with self._thread_lock:
            if self._shutting_down:
                return
            self._shutting_down = True
            worker = self._worker
        if worker is not None and worker.is_alive():
            try:
                self._queue.put(None, timeout=1.0)
            except queue.Full:
                pass
            worker.join(timeout=max(0.2, timeout))
        with self._thread_lock:
            self._worker = None

    def _writer_loop(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=0.05)
            except queue.Empty:
                continue

            batch: list[tuple[LogRecordEntry, bool]] = []
            flush_events: list[threading.Event] = []
            stop_requested = False

            pending_items = [item]
            while len(batch) < 200:
                if pending_items:
                    obj = pending_items.pop(0)
                else:
                    try:
                        obj = self._queue.get_nowait()
                    except queue.Empty:
                        break
                if obj is None:
                    stop_requested = True
                elif isinstance(obj, threading.Event):
                    flush_events.append(obj)
                elif isinstance(obj, tuple) and len(obj) == 2:
                    batch.append(obj)

            if batch:
                self._write_batch(batch)
            for ev in flush_events:
                ev.set()
            if stop_requested:
                break

    @contextmanager
    def _process_lock(self) -> Iterator[None]:
        """Acquire exclusive inter-process file lock so concurrent processes never clash during rotation."""
        self._ensure_dirs()
        fh: io.BufferedRandom | None = None
        locked = False
        try:
            fh = open(self._lock_path, "a+b")
            deadline = time.monotonic() + 5.0
            while True:
                try:
                    if sys.platform == "win32":
                        import msvcrt

                        fh.seek(0)
                        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.008)
            yield
        except OSError as exc:
            self._record_io_error(exc)
            yield
        finally:
            if fh is not None:
                if locked:
                    try:
                        if sys.platform == "win32":
                            import msvcrt

                            fh.seek(0)
                            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                        else:
                            import fcntl

                            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                    except OSError:
                        pass
                try:
                    fh.close()
                except OSError:
                    pass

    def _write_batch(self, batch: list[tuple[LogRecordEntry, bool]]) -> None:
        cfg = self.config
        if not self._ensure_dirs():
            return
        grouped: dict[str, list[str]] = {}
        for entry, mirror_errors in batch:
            line = entry.format_line()
            grouped.setdefault(entry.component, []).append(line)
            if mirror_errors and LEVEL_RANK[entry.level] >= LEVEL_RANK["ERROR"] and entry.component != "errors":
                grouped.setdefault("errors", []).append(line)

        max_bytes = cfg.max_file_mb * 1024 * 1024
        with self._process_lock():
            for comp, lines in grouped.items():
                payload = ("\n".join(lines) + "\n").encode("utf-8", errors="replace")
                target = self.component_path(comp)
                try:
                    if cfg.auto_rotate and target.exists():
                        if target.stat().st_size + len(payload) > max_bytes:
                            self._rotate_file_locked(target, comp, cfg)
                    with open(target, "ab") as fh:
                        fh.write(payload)
                        fh.flush()
                except OSError as exc:
                    self._record_io_error(exc)
            self._enforce_retention_locked(cfg)

    def _rotate_file_locked(self, target: Path, component: str, cfg: LogConfig) -> None:
        """Rotate target file to archive (.log.gz if archiving enabled, else overwrite/trim)."""
        if not target.is_file():
            return
        if cfg.archive_enabled:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
            rotated = self._archive_dir / f"{component}_{stamp}_{os.getpid()}.log"
            try:
                target.replace(rotated)
            except OSError as exc:
                self._record_io_error(exc)
                return
            gz_path = rotated.with_name(rotated.name + ".gz")
            try:
                with open(rotated, "rb") as src, gzip.open(gz_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                rotated.unlink(missing_ok=True)
            except OSError as exc:
                self._record_io_error(exc)
        else:
            rotated = self._archive_dir / f"{component}.1.log"
            try:
                if rotated.exists():
                    rotated.unlink(missing_ok=True)
                target.replace(rotated)
            except OSError as exc:
                self._record_io_error(exc)

    def _enforce_retention_locked(self, cfg: LogConfig) -> None:
        """Prune expired archives first, then oldest archives down to ``max_total_mb`` (never audits)."""
        now = time.time()
        max_age_s = cfg.retention_days * 86400
        try:
            archives = [
                p for p in self._archive_dir.iterdir()
                if p.is_file() and p.name not in _PROTECTED_AUDIT_NAMES
            ]
        except OSError:
            archives = []

        kept_archives: list[Path] = []
        for item in archives:
            try:
                if (now - item.stat().st_mtime) > max_age_s:
                    item.unlink(missing_ok=True)
                else:
                    kept_archives.append(item)
            except OSError:
                continue

        limit_bytes = cfg.max_total_mb * 1024 * 1024
        total = self._total_log_bytes_locked()
        if total <= limit_bytes:
            return

        # Delete oldest archives first
        kept_archives.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0.0)
        for arch in kept_archives:
            if total <= limit_bytes:
                break
            try:
                sz = arch.stat().st_size
                arch.unlink(missing_ok=True)
                total = max(0, total - sz)
            except OSError:
                continue

    def _total_log_bytes_locked(self) -> int:
        total = 0
        for folder in (self._base_dir, self._archive_dir):
            try:
                for p in folder.iterdir():
                    if p.is_file() and p.name != self._lock_path.name and p.name not in _PROTECTED_AUDIT_NAMES:
                        try:
                            total += p.stat().st_size
                        except OSError:
                            pass
            except OSError:
                pass
        return total

    def total_size_bytes(self) -> int:
        with self._process_lock():
            return self._total_log_bytes_locked()

    def clear_normal_logs(self, component: str | None = None) -> int:
        """Clear standard log files and archives while NEVER touching protected security audit logs."""
        self.flush(timeout=2.0)
        cleared = 0
        with self._process_lock():
            targets = [normalize_component(component)] if component and component != "all" else list(LOG_COMPONENTS)
            for comp in targets:
                p = self.component_path(comp)
                if p.name in _PROTECTED_AUDIT_NAMES:
                    continue
                if p.exists():
                    try:
                        p.write_text("", encoding="utf-8")
                        cleared += 1
                    except OSError as exc:
                        self._record_io_error(exc)
            if not component or component == "all":
                try:
                    for item in self._archive_dir.iterdir():
                        if item.is_file() and item.name not in _PROTECTED_AUDIT_NAMES:
                            item.unlink(missing_ok=True)
                except OSError as exc:
                    self._record_io_error(exc)
        return cleared

    def read_tail_page(
        self,
        component: str = "all",
        *,
        offset_from_end: int = 0,
        max_bytes: int = 131072,
        max_lines: int = 500,
    ) -> tuple[list[dict[str, str]], int, bool]:
        """Stream-read a bounded slice from the tail of one or all logs without loading entire large files.

        Returns ``(parsed_records, next_offset_from_end, has_more)``.
        """
        if component == "all":
            collected: list[dict[str, str]] = []
            for comp in LOG_COMPONENTS:
                if comp == "errors":
                    continue  # already mirrored from individual components
                recs, _, _ = self.read_tail_page(
                    comp,
                    offset_from_end=offset_from_end,
                    max_bytes=max(16384, max_bytes // max(1, len(LOG_COMPONENTS) - 1)),
                    max_lines=max(40, max_lines // 4),
                )
                collected.extend(recs)
            collected.sort(key=lambda r: r.get("timestamp") or "")
            return collected[-max_lines:], 0, False

        target = self.component_path(component)
        if not target.is_file():
            return [], offset_from_end, False
        try:
            size = target.stat().st_size
            if size == 0 or offset_from_end >= size:
                return [], size, False
            end_pos = max(0, size - max(0, offset_from_end))
            start_pos = max(0, end_pos - max(4096, max_bytes))
            with open(target, "rb") as fh:
                fh.seek(start_pos)
                chunk = fh.read(end_pos - start_pos)
            text = chunk.decode("utf-8", errors="replace")
            lines = text.splitlines()
            if start_pos > 0 and lines:
                # Drop partial leading line when seeking into the middle of the file.
                first_nl = chunk.find(b"\n")
                if first_nl >= 0:
                    start_pos += first_nl + 1
                lines = lines[1:]
            selected = lines[-max_lines:]
            records = [
                parse_log_line(self._redactor.redact_text(line), fallback_component=component)
                for line in selected
                if line.strip()
            ]
            next_offset = size - start_pos
            has_more = start_pos > 0
            return records, next_offset, has_more
        except OSError as exc:
            self._record_io_error(exc)
            return [], offset_from_end, False

    def _record_io_error(self, exc: OSError) -> None:
        self._write_failures += 1
        now = time.monotonic()
        if now - self._last_io_error_ts > 5.0:
            self._last_io_error_ts = now
            self.last_io_error = f"{type(exc).__name__}: {exc}"


_GLOBAL_LOCK = threading.Lock()
_GLOBAL_MANAGER: LoggingManager | None = None


def get_logging_manager() -> LoggingManager:
    global _GLOBAL_MANAGER
    with _GLOBAL_LOCK:
        if _GLOBAL_MANAGER is None:
            _GLOBAL_MANAGER = LoggingManager(auto_start=True)
            atexit.register(_shutdown_global)
        return _GLOBAL_MANAGER


def configure_logging(
    *,
    base_dir: Path | None = None,
    config: LogConfig | None = None,
    redactor: SecretRedactor | None = None,
    data_root: Path | None = None,
) -> LoggingManager:
    global _GLOBAL_MANAGER
    with _GLOBAL_LOCK:
        if _GLOBAL_MANAGER is None:
            _GLOBAL_MANAGER = LoggingManager(base_dir=base_dir, config=config, redactor=redactor, auto_start=False)
            _GLOBAL_MANAGER.initialize(data_root=data_root)
            atexit.register(_shutdown_global)
        else:
            if base_dir is not None and Path(base_dir).expanduser() != _GLOBAL_MANAGER.base_dir:
                _GLOBAL_MANAGER.set_base_dir(base_dir)
            if config is not None:
                _GLOBAL_MANAGER.update_config(config)
            if redactor is not None:
                _GLOBAL_MANAGER._redactor = redactor
            _GLOBAL_MANAGER.initialize(data_root=data_root)
        return _GLOBAL_MANAGER


def _shutdown_global() -> None:
    mgr = _GLOBAL_MANAGER
    if mgr is not None:
        mgr.shutdown(timeout=1.5)
