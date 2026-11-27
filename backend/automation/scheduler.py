"""Scheduler with 5-field cron, TZ/DST, misfire/concurrency policies, cross-process locking & async lifecycle."""
from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import secrets
import sys
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, Callable, Iterator
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import psutil

from app.core.atomic_io import atomic_write_json, try_init_private_dir
from app.core.redaction import SecretRedactor
from app.paths import user_data_dir

SCHEDULES_SCHEMA_VERSION = 2
HISTORY_SCHEMA_VERSION = 1
ACTIVE_RUNS_SCHEMA_VERSION = 1

_OFFSET_RE = re.compile(r"^(?:UTC|GMT)?([+-])(\d{1,2}):?(\d{2})$", re.IGNORECASE)
_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
_RESERVED_CLIENT_IDS = frozenset({"mcp-app-user"})

_PATH_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[Path, threading.RLock] = {}
_PATH_LOCK_DEPTH: dict[tuple[Path, int], int] = {}


def _get_path_lock(base_dir: Path) -> threading.RLock:
    resolved = Path(base_dir).resolve()
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(resolved)
        if lock is None:
            lock = threading.RLock()
            _PATH_LOCKS[resolved] = lock
        return lock


if sys.platform == "win32":
    import msvcrt

    def _win32_lock_fd(fd: int, timeout: float, lock_path: Path) -> None:
        deadline = time.monotonic() + max(0.5, timeout)
        while True:
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Timed out waiting for scheduler lock: {lock_path}") from None
                time.sleep(0.01)

    def _win32_unlock_fd(fd: int) -> None:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass

    @contextmanager
    def _os_file_lock(lock_path: Path, timeout: float = 10.0) -> Iterator[None]:
        """Acquire a cross-process byte lock on `lock_path` (Win32)."""
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            _win32_lock_fd(fd, timeout, lock_path)
            try:
                yield
            finally:
                _win32_unlock_fd(fd)
        finally:
            os.close(fd)
else:
    import fcntl

    @contextmanager
    def _os_file_lock(lock_path: Path, timeout: float = 10.0) -> Iterator[None]:
        """Acquire a cross-process flock on `lock_path` (POSIX)."""
        del timeout
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            os.close(fd)


def _validate_client_id(raw: object) -> str:
    if not isinstance(raw, str):
        raise ValueError("Invalid client_id")
    clean = raw.strip()
    if not _CLIENT_ID_RE.fullmatch(clean) or clean in _RESERVED_CLIENT_IDS:
        raise ValueError(f"Invalid schedule client_id: {raw!r}")
    return clean


def resolve_timezone(name: str) -> tzinfo:
    """Resolve IANA ZoneInfo, 'UTC', 'local', or '+HH:MM' safely without failing on missing tzdata."""
    clean = (name or "UTC").strip()
    if not clean or clean.upper() in ("UTC", "Z"):
        return timezone.utc
    if clean.lower() == "local":
        return datetime.now().astimezone().tzinfo or timezone.utc
    m = _OFFSET_RE.match(clean)
    if m:
        sign = 1 if m.group(1) == "+" else -1
        delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3))) * sign
        return timezone(delta)
    try:
        return ZoneInfo(clean)
    except ZoneInfoNotFoundError:
        return timezone.utc


def _parse_field(expr: str, lo: int, hi: int) -> frozenset[int]:
    out: set[int] = set()
    for part in expr.split(","):
        p = part.strip()
        if not p:
            raise ValueError(f"Empty cron field token in {expr!r}")
        step = 1
        if "/" in p:
            base, step_s = p.split("/", 1)
            step = int(step_s)
            if step <= 0:
                raise ValueError(f"Cron step must be > 0: {p!r}")
        else:
            base = p
        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            a, b = base.split("-", 1)
            start, end = int(a), int(b)
        else:
            val = int(base)
            start = end = val
        if not (lo <= start <= end <= hi):
            raise ValueError(f"Cron value out of range [{lo}..{hi}]: {p!r}")
        out.update(range(start, end + 1, step))
    if not out:
        raise ValueError(f"Cron field produced empty set: {expr!r}")
    return frozenset(out)


def parse_cron_expr(expr: str) -> tuple[frozenset[int], frozenset[int], frozenset[int], frozenset[int], frozenset[int]]:
    """Parse standard 5-field cron (`minute hour day month weekday`, 0=Sun or 7=Sun/Mon=1..Sat=6)."""
    fields = (expr or "").split()
    if len(fields) != 5:
        raise ValueError(f"Cron expression must have 5 fields: {expr!r}")
    mins = _parse_field(fields[0], 0, 59)
    hrs = _parse_field(fields[1], 0, 23)
    dom = _parse_field(fields[2], 1, 31)
    months = _parse_field(fields[3], 1, 12)
    raw_dow = _parse_field(fields[4], 0, 7)
    dow = frozenset(0 if d == 7 else d for d in raw_dow)
    return mins, hrs, dom, months, dow


def next_cron_timestamp(
    expr: str,
    after_ts: float,
    *,
    tz_name: str = "UTC",
    max_search_days: int = 366,
) -> float:
    """Compute next UTC timestamp matching 5-field `expr` strictly after `after_ts`, DST-aware."""
    mins, hrs, dom, months, dow = parse_cron_expr(expr)
    tz = resolve_timezone(tz_name)
    start_utc = datetime.fromtimestamp(after_ts, tz=timezone.utc).replace(second=0, microsecond=0) + timedelta(minutes=1)
    limit = int(max_search_days) * 24 * 60
    cur_utc = start_utc
    for _ in range(limit):
        local_dt = cur_utc.astimezone(tz)
        cron_dow = (local_dt.weekday() + 1) % 7
        if (
            local_dt.minute in mins
            and local_dt.hour in hrs
            and local_dt.day in dom
            and local_dt.month in months
            and cron_dow in dow
        ):
            return cur_utc.timestamp()
        cur_utc += timedelta(minutes=1)
    raise ValueError(f"No matching cron time within {max_search_days} days for {expr!r}")


@dataclass
class ScheduleSpec:
    """Persistent scheduled automation rule."""

    schedule_id: str
    name: str
    trigger_type: str  # cron | interval | startup | event
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    cron_expr: str = "*/5 * * * *"
    interval_seconds: int = 300
    event_name: str = ""
    timezone_name: str = "UTC"
    client_id: str = "owner"
    misfire_policy: str = "skip"  # skip | coalesce | run_once
    concurrency_policy: str = "forbid"  # forbid | allow
    safe_retry: bool = False
    max_retries: int = 0
    idempotency_key: str = ""
    enabled: bool = True
    paused_reason: str = ""
    last_run_at: float = 0.0
    next_run_at: float = 0.0
    live_execution_approved: bool = True

    def __post_init__(self) -> None:
        clean_id = (self.schedule_id or "").strip()
        if not _ID_RE.match(clean_id):
            raise ValueError(f"Invalid schedule_id: {self.schedule_id!r}")
        self.schedule_id = clean_id
        self.name = (self.name or clean_id).strip()
        if self.trigger_type not in ("cron", "interval", "startup", "event"):
            raise ValueError(f"Unsupported trigger_type: {self.trigger_type!r}")
        if self.trigger_type == "cron":
            parse_cron_expr(self.cron_expr)
        elif self.trigger_type == "interval":
            self.interval_seconds = max(5, int(self.interval_seconds))
        elif self.trigger_type == "event" and not (self.event_name or "").strip():
            raise ValueError("event_name is required for event triggers")
        if self.misfire_policy not in ("skip", "coalesce", "run_once"):
            raise ValueError(f"Unsupported misfire_policy: {self.misfire_policy!r}")
        if self.concurrency_policy not in ("forbid", "allow"):
            raise ValueError(f"Unsupported concurrency_policy: {self.concurrency_policy!r}")
        if not self.safe_retry and int(self.max_retries) > 0:
            raise ValueError("Unsafe/mutating schedules with safe_retry=False cannot enable automatic retries")
        self.max_retries = max(0, min(int(self.max_retries), 3))
        if not (self.tool_name or "").strip():
            raise ValueError("tool_name is required")
        self.client_id = _validate_client_id(self.client_id)
        self.live_execution_approved = bool(self.live_execution_approved)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schedule_id": self.schedule_id,
            "name": self.name,
            "trigger_type": self.trigger_type,
            "tool_name": self.tool_name,
            "arguments": dict(self.arguments),
            "cron_expr": self.cron_expr,
            "interval_seconds": self.interval_seconds,
            "event_name": self.event_name,
            "timezone_name": self.timezone_name,
            "client_id": self.client_id,
            "misfire_policy": self.misfire_policy,
            "concurrency_policy": self.concurrency_policy,
            "safe_retry": self.safe_retry,
            "max_retries": self.max_retries,
            "idempotency_key": self.idempotency_key,
            "enabled": self.enabled,
            "paused_reason": self.paused_reason,
            "last_run_at": self.last_run_at,
            "next_run_at": self.next_run_at,
            "live_execution_approved": self.live_execution_approved,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, default_live_approved: bool = True) -> ScheduleSpec:
        return cls(
            schedule_id=str(data.get("schedule_id") or ""),
            name=str(data.get("name") or ""),
            trigger_type=str(data.get("trigger_type") or "interval"),
            tool_name=str(data.get("tool_name") or ""),
            arguments=dict(data.get("arguments") or {}),
            cron_expr=str(data.get("cron_expr") or "*/5 * * * *"),
            interval_seconds=int(data.get("interval_seconds") or 300),
            event_name=str(data.get("event_name") or ""),
            timezone_name=str(data.get("timezone_name") or "UTC"),
            client_id=(
                str(data["client_id"])
                if "client_id" in data and data["client_id"] is not None
                else ("" if "client_id" in data else "owner")
            ),
            misfire_policy=str(data.get("misfire_policy") or "skip"),
            concurrency_policy=str(data.get("concurrency_policy") or "forbid"),
            safe_retry=bool(data.get("safe_retry", False)),
            max_retries=int(data.get("max_retries") or 0),
            idempotency_key=str(data.get("idempotency_key") or ""),
            enabled=bool(data.get("enabled", True)),
            paused_reason=str(data.get("paused_reason") or ""),
            last_run_at=float(data.get("last_run_at") or 0.0),
            next_run_at=float(data.get("next_run_at") or 0.0),
            live_execution_approved=bool(data.get("live_execution_approved", default_live_approved)),
        )


@dataclass
class ScheduleRunRecord:
    """Recorded execution attempt for one schedule trigger."""

    run_id: str
    schedule_id: str
    trigger: str
    started_at: float
    finished_at: float = 0.0
    status: str = "succeeded"
    idempotency_key: str = ""
    attempts: int = 1
    result_summary: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "schedule_id": self.schedule_id,
            "trigger": self.trigger,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "idempotency_key": self.idempotency_key,
            "attempts": self.attempts,
            "result_summary": self.result_summary,
            "error": self.error,
        }


class AutomationScheduler:
    """Locked, persistent scheduler supporting sync/async execution, permissions, and lifecycle."""

    def __init__(
        self,
        base_dir: Path | None = None,
        *,
        executor: Callable[[ScheduleSpec, str], Any] | None = None,
        async_executor: Callable[[ScheduleSpec, str], Any] | None = None,
        permission_checker: Callable[[ScheduleSpec], tuple[bool, str]] | None = None,
        notifier: Callable[[str, str], None] | None = None,
        redactor: SecretRedactor | None = None,
        execution_timeout: float = 120.0,
    ) -> None:
        self.base_dir = Path(base_dir) if base_dir is not None else (user_data_dir() / "automation")
        try_init_private_dir(self.base_dir)
        self.schedules_path = self.base_dir / "schedules.json"
        self.history_path = self.base_dir / "history.json"
        self.active_runs_path = self.base_dir / "active_runs.json"
        self._lock_path = self.base_dir / ".automation.lock"
        self._executor = executor
        self._async_executor = async_executor
        self._permission_checker = permission_checker
        self._notifier = notifier
        self._redactor = redactor or SecretRedactor()
        self._execution_timeout = max(0.05, float(execution_timeout))
        self._lock = threading.RLock()
        self._resolved_dir = self.base_dir.resolve()
        self._path_lock = _get_path_lock(self._resolved_dir)
        self._active_ids: set[str] = set()
        self._seen_idempotency: deque[str] = deque(maxlen=500)
        self._notifications: deque[dict[str, Any]] = deque(maxlen=100)
        self._bg_stop_event: asyncio.Event | None = None
        self._bg_task: asyncio.Task[None] | None = None
        self._inflight_tasks: set[asyncio.Task[Any]] = set()

    @property
    def is_running(self) -> bool:
        return self._bg_task is not None and not self._bg_task.done()

    @contextmanager
    def _state_lock(self) -> Iterator[None]:
        with self._lock:
            with self._path_lock:
                key = (self._resolved_dir, threading.get_ident())
                depth = _PATH_LOCK_DEPTH.get(key, 0)
                _PATH_LOCK_DEPTH[key] = depth + 1
                try:
                    if depth == 0:
                        with _os_file_lock(self._lock_path):
                            yield
                    else:
                        yield
                finally:
                    if depth == 0:
                        _PATH_LOCK_DEPTH.pop(key, None)
                    else:
                        _PATH_LOCK_DEPTH[key] = depth

    def _atomic_write_json(self, path: Path, payload: dict[str, Any]) -> None:
        atomic_write_json(path, payload, indent=2, restrict_acl=True)

    @staticmethod
    def _parse_schedule_entry(
        rec: object, *, legacy_file: bool
    ) -> tuple[ScheduleSpec | None, bool]:
        if not isinstance(rec, dict):
            return (None, False)
        try:
            sp = ScheduleSpec.from_dict(rec, default_live_approved=not legacy_file)
        except (ValueError, TypeError):
            return (None, False)
        if not legacy_file or sp.live_execution_approved:
            return (sp, False)
        if sp.enabled:
            sp.enabled = False
            sp.paused_reason = (
                sp.paused_reason
                or "Paused after upgrade: owner approval required for live execution"
            )
        return (sp, True)

    def _load_schedules_unlocked(self, *, persist_migration: bool = True) -> dict[str, ScheduleSpec]:
        if not self.schedules_path.is_file():
            return {}
        try:
            raw = json.loads(self.schedules_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(raw, dict):
            return {}
        legacy_file = int(raw.get("version") or 1) < SCHEDULES_SCHEMA_VERSION
        items = raw.get("schedules")
        if not isinstance(items, dict):
            return {}
        out: dict[str, ScheduleSpec] = {}
        migrated = False
        for rec in items.values():
            sp, changed_entry = self._parse_schedule_entry(rec, legacy_file=legacy_file)
            if sp is not None:
                out[sp.schedule_id] = sp
                migrated = migrated or changed_entry
        if persist_migration and (legacy_file or migrated):
            self._save_schedules_unlocked(out)
        return out

    def _save_schedules_unlocked(self, items: dict[str, ScheduleSpec]) -> None:
        self._atomic_write_json(
            self.schedules_path,
            {
                "version": SCHEDULES_SCHEMA_VERSION,
                "schedules": {k: v.to_dict() for k, v in sorted(items.items())},
            },
        )

    def _append_history_unlocked(self, rec: ScheduleRunRecord) -> None:
        rows: list[dict[str, Any]] = []
        if self.history_path.is_file():
            try:
                raw = json.loads(self.history_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict) and isinstance(raw.get("runs"), list):
                    rows = list(raw["runs"])
            except (OSError, json.JSONDecodeError):
                rows = []
        rows.append(rec.to_dict())
        rows = rows[-300:]
        self._atomic_write_json(self.history_path, {"version": HISTORY_SCHEMA_VERSION, "runs": rows})

    @staticmethod
    def _is_entry_process_alive(entry: object) -> bool:
        if not isinstance(entry, dict):
            return False
        pid = entry.get("pid")
        ctime = entry.get("create_time")
        if type(pid) is not int or pid <= 0 or not isinstance(ctime, (int, float)) or isinstance(ctime, bool):
            return False
        try:
            proc = psutil.Process(pid)
            return proc.is_running() and abs(float(proc.create_time()) - float(ctime)) <= 2.0
        except psutil.NoSuchProcess:
            return False
        except (psutil.Error, OSError):
            return True

    def _load_active_runs_unlocked(self) -> dict[str, dict[str, Any]]:
        if not self.active_runs_path.is_file():
            return {}
        try:
            raw = json.loads(self.active_runs_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(raw, dict) or raw.get("version") != ACTIVE_RUNS_SCHEMA_VERSION:
            return {}
        active = raw.get("active")
        if not isinstance(active, dict):
            return {}
        return {str(k): v for k, v in active.items() if isinstance(k, str) and self._is_entry_process_alive(v)}

    def _record_active_run_unlocked(self, run_id: str, schedule_id: str, trigger: str, started_at: float) -> None:
        active = self._load_active_runs_unlocked()
        try:
            proc_ctime = float(psutil.Process(os.getpid()).create_time())
        except (psutil.Error, OSError):
            proc_ctime = started_at
        active[run_id] = {
            "run_id": run_id,
            "schedule_id": schedule_id,
            "trigger": trigger,
            "started_at": started_at,
            "pid": os.getpid(),
            "create_time": proc_ctime,
        }
        self._atomic_write_json(self.active_runs_path, {"version": ACTIVE_RUNS_SCHEMA_VERSION, "active": active})

    def _remove_active_run_unlocked(self, schedule_id: str, run_id: str = "") -> None:
        if not self.active_runs_path.is_file() and not run_id:
            return
        active = self._load_active_runs_unlocked()
        if run_id:
            active.pop(run_id, None)
        else:
            my_pid = os.getpid()
            active = {
                k: v
                for k, v in active.items()
                if not (v.get("schedule_id") == schedule_id and v.get("pid") == my_pid)
            }
        self._atomic_write_json(self.active_runs_path, {"version": ACTIVE_RUNS_SCHEMA_VERSION, "active": active})

    def has_active_runs(self) -> bool:
        """Return True if any schedule run is currently active in memory."""
        with self._lock:
            return bool(self._active_ids)

    def _notify(self, title: str, body: str) -> None:
        redacted_body = self._redactor.redact_text(body)
        entry: dict[str, Any] = {"ts": time.time(), "title": title, "body": redacted_body}
        with self._lock:
            self._notifications.append(entry)
        if self._notifier is not None:
            try:
                self._notifier(title, redacted_body)
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def check_actor_can_mutate(*, actor_id: str, actor_profile: str) -> str:
        clean_actor = _validate_client_id(actor_id)
        if clean_actor != "owner" and actor_profile != "full":
            raise PermissionError("Modifying automation schedules requires owner or Full Access profile")
        return clean_actor

    def _safe_check_permission(self, spec: ScheduleSpec) -> tuple[bool, str]:
        if self._permission_checker is None:
            return (True, "")
        try:
            res = self._permission_checker(spec)
            if not isinstance(res, tuple) or len(res) != 2:
                return (False, "Invalid authorization check result")
            return (bool(res[0]), str(res[1] or ""))
        except Exception as exc:  # noqa: BLE001
            return (False, f"Authorization check error: {type(exc).__name__}")

    def list_schedules(self) -> list[dict[str, Any]]:
        with self._state_lock():
            return [s.to_dict() for s in self._load_schedules_unlocked().values()]

    def list_history(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._state_lock():
            if not self.history_path.is_file():
                return []
            try:
                raw = json.loads(self.history_path.read_text(encoding="utf-8"))
                runs = raw.get("runs") if isinstance(raw, dict) else []
                return list(runs[-max(1, min(int(limit), 300)):]) if isinstance(runs, list) else []
            except (OSError, json.JSONDecodeError):
                return []

    def notifications(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._notifications)

    def upsert_schedule(
        self,
        spec: ScheduleSpec,
        *,
        actor_id: str = "owner",
        actor_profile: str = "full",
        now: float | None = None,
    ) -> dict[str, Any]:
        clean_actor = self.check_actor_can_mutate(actor_id=actor_id, actor_profile=actor_profile)
        if clean_actor != "owner" and spec.client_id != clean_actor:
            raise PermissionError("OAuth client schedules must bind client_id to the calling actor")
        if self._permission_checker is not None:
            allowed, reason = self._safe_check_permission(spec)
            if clean_actor != "owner" and not allowed:
                raise PermissionError(reason or "Client is not authorized for scheduled tool or arguments")
        if clean_actor == "owner":
            spec.live_execution_approved = True
        ts = time.time() if now is None else float(now)
        if spec.enabled and spec.next_run_at <= 0.0:
            spec.next_run_at = self._compute_next_run(spec, ts)
        with self._state_lock():
            all_s = self._load_schedules_unlocked()
            existing = all_s.get(spec.schedule_id)
            if clean_actor != "owner" and existing is not None and existing.client_id != clean_actor:
                raise PermissionError("Cannot overwrite a schedule owned by another principal")
            all_s[spec.schedule_id] = spec
            self._save_schedules_unlocked(all_s)
        return spec.to_dict()

    def _apply_enable_change(
        self, spec: ScheduleSpec, enabled: bool, *, clean_actor: str, ts: float
    ) -> None:
        if not enabled:
            spec.enabled = False
            spec.paused_reason = "Paused by owner"
            return
        if self._permission_checker is not None:
            allowed, reason = self._safe_check_permission(spec)
            if not allowed:
                raise PermissionError(reason or "Scheduled tool is not currently authorized")
        spec.enabled = True
        spec.paused_reason = ""
        if clean_actor == "owner":
            spec.live_execution_approved = True
        if spec.trigger_type in ("cron", "interval") and spec.next_run_at <= ts:
            spec.next_run_at = self._compute_next_run(spec, ts)

    def set_schedule_enabled(
        self,
        schedule_id: str,
        enabled: bool,
        *,
        actor_id: str = "owner",
        actor_profile: str = "full",
        now: float | None = None,
    ) -> dict[str, Any]:
        clean_actor = self.check_actor_can_mutate(actor_id=actor_id, actor_profile=actor_profile)
        ts = time.time() if now is None else float(now)
        with self._state_lock():
            all_s = self._load_schedules_unlocked()
            spec = all_s.get(schedule_id)
            if spec is None:
                raise KeyError(f"Unknown schedule: {schedule_id}")
            if clean_actor != "owner" and spec.client_id != clean_actor:
                raise PermissionError("Cannot modify a schedule owned by another principal")
            self._apply_enable_change(spec, enabled, clean_actor=clean_actor, ts=ts)
            all_s[schedule_id] = spec
            self._save_schedules_unlocked(all_s)
            return spec.to_dict()

    def remove_schedule(
        self,
        schedule_id: str,
        *,
        actor_id: str = "owner",
        actor_profile: str = "full",
    ) -> bool:
        clean_actor = self.check_actor_can_mutate(actor_id=actor_id, actor_profile=actor_profile)
        with self._state_lock():
            all_s = self._load_schedules_unlocked()
            existing = all_s.get(schedule_id)
            if existing is None:
                return False
            if clean_actor != "owner" and existing.client_id != clean_actor:
                raise PermissionError("Cannot remove a schedule owned by another principal")
            all_s.pop(schedule_id, None)
            self._save_schedules_unlocked(all_s)
            return True

    @staticmethod
    def _compute_next_run(spec: ScheduleSpec, after_ts: float) -> float:
        if spec.trigger_type == "cron":
            return next_cron_timestamp(spec.cron_expr, after_ts, tz_name=spec.timezone_name)
        if spec.trigger_type == "interval":
            return after_ts + max(5, spec.interval_seconds)
        return 0.0

    @staticmethod
    def _build_idem_key(spec: ScheduleSpec, idem_suffix: str) -> str:
        if spec.idempotency_key or idem_suffix:
            return f"{spec.schedule_id}:{spec.idempotency_key}:{idem_suffix}"
        return ""

    def _resolve_timeout(self, spec: ScheduleSpec) -> float:
        raw_to = spec.arguments.get("timeout") if isinstance(spec.arguments, dict) else None
        if isinstance(raw_to, (int, float)) and not isinstance(raw_to, bool) and raw_to > 0:
            return min(615.0, max(float(self._execution_timeout), float(raw_to) + 5.0))
        return self._execution_timeout

    def _claim_execution_slot(
        self,
        spec: ScheduleSpec,
        *,
        trigger: str,
        idem_suffix: str,
        now: float,
    ) -> tuple[str, str, ScheduleRunRecord | None]:
        run_id = secrets.token_hex(6)
        idem = self._build_idem_key(spec, idem_suffix)
        with self._state_lock():
            if idem and idem in self._seen_idempotency:
                rec = ScheduleRunRecord(
                    run_id=run_id,
                    schedule_id=spec.schedule_id,
                    trigger=trigger,
                    started_at=now,
                    finished_at=now,
                    status="skipped_idempotent",
                    idempotency_key=idem,
                )
                self._append_history_unlocked(rec)
                return (run_id, idem, rec)
            if spec.concurrency_policy == "forbid" and spec.schedule_id in self._active_ids:
                rec = ScheduleRunRecord(
                    run_id=run_id,
                    schedule_id=spec.schedule_id,
                    trigger=trigger,
                    started_at=now,
                    finished_at=now,
                    status="skipped_concurrency",
                )
                self._append_history_unlocked(rec)
                return (run_id, idem, rec)
            self._active_ids.add(spec.schedule_id)
            if idem:
                self._seen_idempotency.append(idem)
            self._record_active_run_unlocked(run_id, spec.schedule_id, trigger, now)
            return (run_id, idem, None)

    def _pause_revoked(
        self,
        spec: ScheduleSpec,
        *,
        run_id: str,
        trigger: str,
        idem: str,
        now: float,
        attempts: int,
        reason: str,
    ) -> ScheduleRunRecord:
        err_text = reason or "Permission revoked"
        with self._state_lock():
            all_s = self._load_schedules_unlocked()
            stored = all_s.get(spec.schedule_id)
            if stored is not None:
                stored.enabled = False
                stored.paused_reason = err_text
                self._save_schedules_unlocked(all_s)
            rec = ScheduleRunRecord(
                run_id=run_id,
                schedule_id=spec.schedule_id,
                trigger=trigger,
                started_at=now,
                finished_at=time.time(),
                status="paused_revoked",
                idempotency_key=idem,
                attempts=max(1, attempts),
                error=err_text,
            )
            self._append_history_unlocked(rec)
        self._notify("Schedule Paused", f"{spec.name}: {err_text}")
        return rec

    def _record_success(
        self,
        spec: ScheduleSpec,
        *,
        run_id: str,
        trigger: str,
        idem: str,
        now: float,
        attempts: int,
        out: Any,
    ) -> ScheduleRunRecord:
        redacted_out = self._redactor.redact_mapping(out)
        summary = self._redactor.redact_text(
            json.dumps(redacted_out, ensure_ascii=False, default=str)[:500]
        )
        rec = ScheduleRunRecord(
            run_id=run_id,
            schedule_id=spec.schedule_id,
            trigger=trigger,
            started_at=now,
            finished_at=time.time(),
            status="succeeded",
            idempotency_key=idem,
            attempts=attempts,
            result_summary=summary,
        )
        with self._state_lock():
            all_s = self._load_schedules_unlocked()
            if spec.schedule_id in all_s:
                all_s[spec.schedule_id].last_run_at = rec.finished_at
                self._save_schedules_unlocked(all_s)
            self._append_history_unlocked(rec)
        return rec

    def _record_failure(
        self,
        spec: ScheduleSpec,
        *,
        run_id: str,
        trigger: str,
        idem: str,
        now: float,
        attempts: int,
        last_err: str,
        status: str = "failed",
    ) -> ScheduleRunRecord:
        rec = ScheduleRunRecord(
            run_id=run_id,
            schedule_id=spec.schedule_id,
            trigger=trigger,
            started_at=now,
            finished_at=time.time(),
            status=status,
            idempotency_key=idem,
            attempts=max(1, attempts),
            error=last_err,
        )
        with self._state_lock():
            self._append_history_unlocked(rec)
        if status != "cancelled":
            self._notify("Schedule Failed", f"{spec.name}: {last_err}")
        return rec

    def _release_slot(self, schedule_id: str, run_id: str = "") -> None:
        with self._state_lock():
            self._active_ids.discard(schedule_id)
            self._remove_active_run_unlocked(schedule_id, run_id)

    def _check_attempt_permission(self, spec: ScheduleSpec) -> tuple[bool, str]:
        if self._permission_checker is None:
            return (True, "")
        return self._safe_check_permission(spec)

    def _invoke_sync_executor(self, spec: ScheduleSpec, idem: str) -> Any:
        if self._executor is None:
            raise RuntimeError("No automation executor configured; backend runtime is required")
        return self._executor(spec, idem)

    async def _invoke_async_executor(self, spec: ScheduleSpec, idem: str) -> Any:
        if self._async_executor is not None:
            res = self._async_executor(spec, idem)
            if inspect.isawaitable(res):
                return await res
            return res
        if self._executor is not None:
            return await asyncio.to_thread(self._executor, spec, idem)
        raise RuntimeError("No automation executor configured; backend runtime is required")

    def _run_claimed_sync(
        self,
        spec: ScheduleSpec,
        *,
        run_id: str,
        trigger: str,
        idem: str,
        now: float,
    ) -> ScheduleRunRecord:
        attempts = 0
        max_attempts = 1 + (spec.max_retries if spec.safe_retry else 0)
        last_err = ""
        try:
            while attempts < max_attempts:
                allowed, reason = self._check_attempt_permission(spec)
                if not allowed:
                    return self._pause_revoked(
                        spec, run_id=run_id, trigger=trigger, idem=idem,
                        now=now, attempts=attempts, reason=reason,
                    )
                attempts += 1
                try:
                    out = self._invoke_sync_executor(spec, idem)
                    return self._record_success(
                        spec, run_id=run_id, trigger=trigger, idem=idem,
                        now=now, attempts=attempts, out=out,
                    )
                except Exception as exc:  # noqa: BLE001
                    last_err = self._redactor.redact_text(str(exc)) or type(exc).__name__
                    if not spec.safe_retry or attempts >= max_attempts:
                        break
            return self._record_failure(
                spec, run_id=run_id, trigger=trigger, idem=idem,
                now=now, attempts=attempts, last_err=last_err,
            )
        finally:
            self._release_slot(spec.schedule_id, run_id)

    async def _attempt_once_async(
        self,
        spec: ScheduleSpec,
        *,
        run_id: str,
        trigger: str,
        idem: str,
        now: float,
        attempts: int,
        attempt_timeout: float,
    ) -> tuple[ScheduleRunRecord | None, str]:
        try:
            out = await asyncio.wait_for(
                self._invoke_async_executor(spec, idem),
                timeout=attempt_timeout,
            )
            rec = self._record_success(
                spec, run_id=run_id, trigger=trigger, idem=idem,
                now=now, attempts=attempts, out=out,
            )
            return (rec, "")
        except asyncio.CancelledError:
            self._record_failure(
                spec, run_id=run_id, trigger=trigger, idem=idem,
                now=now, attempts=attempts,
                last_err="Execution cancelled during shutdown",
                status="cancelled",
            )
            raise
        except TimeoutError:
            return (None, f"Execution timed out after {attempt_timeout:.1f}s")
        except Exception as exc:  # noqa: BLE001
            return (None, self._redactor.redact_text(str(exc)) or type(exc).__name__)

    async def _run_claimed_async(
        self,
        spec: ScheduleSpec,
        *,
        run_id: str,
        trigger: str,
        idem: str,
        now: float,
    ) -> ScheduleRunRecord:
        attempts = 0
        max_attempts = 1 + (spec.max_retries if spec.safe_retry else 0)
        last_err = ""
        attempt_timeout = self._resolve_timeout(spec)
        try:
            while attempts < max_attempts:
                allowed, reason = self._check_attempt_permission(spec)
                if not allowed:
                    return self._pause_revoked(
                        spec, run_id=run_id, trigger=trigger, idem=idem,
                        now=now, attempts=attempts, reason=reason,
                    )
                attempts += 1
                rec, last_err = await self._attempt_once_async(
                    spec, run_id=run_id, trigger=trigger, idem=idem,
                    now=now, attempts=attempts, attempt_timeout=attempt_timeout,
                )
                if rec is not None:
                    return rec
                if not spec.safe_retry or attempts >= max_attempts:
                    break
            return self._record_failure(
                spec, run_id=run_id, trigger=trigger, idem=idem,
                now=now, attempts=attempts, last_err=last_err,
            )
        finally:
            self._release_slot(spec.schedule_id, run_id)

    def _evaluate_due_spec(
        self, spec: ScheduleSpec, *, now: float, reserve_slots: bool
    ) -> tuple[bool, tuple[ScheduleSpec, str, str, str, ScheduleRunRecord | None] | None]:
        if not spec.enabled or not spec.live_execution_approved:
            return (False, None)
        if spec.trigger_type not in ("cron", "interval"):
            return (False, None)
        if spec.next_run_at <= 0.0:
            spec.next_run_at = self._compute_next_run(spec, now)
            return (True, None)
        if now < spec.next_run_at:
            return (False, None)
        overdue_grace = 90.0 if spec.trigger_type == "cron" else float(max(30, spec.interval_seconds))
        if (now - spec.next_run_at) > overdue_grace and spec.misfire_policy == "skip":
            spec.next_run_at = self._compute_next_run(spec, now)
            self._append_history_unlocked(
                ScheduleRunRecord(
                    run_id=secrets.token_hex(6),
                    schedule_id=spec.schedule_id,
                    trigger="misfire_skip",
                    started_at=now,
                    finished_at=now,
                    status="skipped_misfire",
                )
            )
            return (True, None)
        slot_tag = str(int(spec.next_run_at))
        spec.next_run_at = self._compute_next_run(spec, now)
        if not reserve_slots:
            return (True, (spec, slot_tag, "", "", None))
        run_id, idem, skip_rec = self._claim_execution_slot(
            spec, trigger=spec.trigger_type, idem_suffix=slot_tag, now=now
        )
        return (True, (spec, slot_tag, run_id, idem, skip_rec))

    def _collect_due_runs(
        self, *, now: float, reserve_slots: bool
    ) -> list[tuple[ScheduleSpec, str, str, str, ScheduleRunRecord | None]]:
        """Inspect schedules under lock, advance next_run_at, and optionally reserve active slots."""
        due: list[tuple[ScheduleSpec, str, str, str, ScheduleRunRecord | None]] = []
        with self._state_lock():
            all_s = self._load_schedules_unlocked()
            changed = False
            for spec in all_s.values():
                spec_changed, item = self._evaluate_due_spec(
                    spec, now=now, reserve_slots=reserve_slots
                )
                changed = changed or spec_changed
                if item is not None:
                    due.append(item)
            if changed:
                self._save_schedules_unlocked(all_s)
        return due

    def _use_async_via_asyncio_run(self) -> bool:
        if self._executor is not None:
            return False
        if self._async_executor is None:
            return False
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return True
        raise RuntimeError("Call async scheduler methods (trigger_now_async/tick_async) inside an active event loop")

    # ------------------------------------------------------------------ sync API
    def trigger_now(
        self,
        schedule_id: str,
        *,
        trigger: str = "manual",
        idem_suffix: str = "",
        now: float | None = None,
    ) -> dict[str, Any]:
        if self._use_async_via_asyncio_run():
            return asyncio.run(
                self.trigger_now_async(schedule_id, trigger=trigger, idem_suffix=idem_suffix, now=now)
            )
        ts = time.time() if now is None else float(now)
        with self._state_lock():
            spec = self._load_schedules_unlocked().get(schedule_id)
            if spec is None:
                raise KeyError(f"Unknown schedule: {schedule_id}")
            run_id, idem, skip_rec = self._claim_execution_slot(
                spec, trigger=trigger, idem_suffix=idem_suffix, now=ts
            )
        if skip_rec is not None:
            return skip_rec.to_dict()
        return self._run_claimed_sync(spec, run_id=run_id, trigger=trigger, idem=idem, now=ts).to_dict()

    def run_startup_triggers(self, *, now: float | None = None) -> list[dict[str, Any]]:
        if self._use_async_via_asyncio_run():
            return asyncio.run(self.run_startup_triggers_async(now=now))
        ts = time.time() if now is None else float(now)
        with self._state_lock():
            specs = [
                s
                for s in self._load_schedules_unlocked().values()
                if s.enabled and s.live_execution_approved and s.trigger_type == "startup"
            ]
        results: list[dict[str, Any]] = []
        for spec in specs:
            run_id, idem, skip_rec = self._claim_execution_slot(
                spec, trigger="startup", idem_suffix="boot", now=ts
            )
            if skip_rec is not None:
                results.append(skip_rec.to_dict())
            else:
                results.append(
                    self._run_claimed_sync(spec, run_id=run_id, trigger="startup", idem=idem, now=ts).to_dict()
                )
        return results

    def emit_event(
        self, event_name: str, *, payload: dict[str, Any] | None = None, now: float | None = None
    ) -> list[dict[str, Any]]:
        if self._use_async_via_asyncio_run():
            return asyncio.run(self.emit_event_async(event_name, payload=payload, now=now))
        ts = time.time() if now is None else float(now)
        clean_ev = (event_name or "").strip()
        with self._state_lock():
            specs = [
                s
                for s in self._load_schedules_unlocked().values()
                if s.enabled and s.live_execution_approved and s.trigger_type == "event" and s.event_name == clean_ev
            ]
        key = str((payload or {}).get("event_id") or "")
        results: list[dict[str, Any]] = []
        for spec in specs:
            run_id, idem, skip_rec = self._claim_execution_slot(
                spec, trigger=f"event:{clean_ev}", idem_suffix=key, now=ts
            )
            if skip_rec is not None:
                results.append(skip_rec.to_dict())
            else:
                results.append(
                    self._run_claimed_sync(
                        spec, run_id=run_id, trigger=f"event:{clean_ev}", idem=idem, now=ts
                    ).to_dict()
                )
        return results

    def tick(self, *, now: float | None = None) -> list[dict[str, Any]]:
        if self._use_async_via_asyncio_run():
            return asyncio.run(self.tick_async(now=now))
        ts = time.time() if now is None else float(now)
        due = self._collect_due_runs(now=ts, reserve_slots=True)
        out: list[dict[str, Any]] = []
        for spec, _slot_tag, run_id, idem, skip_rec in due:
            if skip_rec is not None:
                out.append(skip_rec.to_dict())
            else:
                out.append(
                    self._run_claimed_sync(spec, run_id=run_id, trigger=spec.trigger_type, idem=idem, now=ts).to_dict()
                )
        return out

    # ------------------------------------------------------------------ async API & lifecycle
    async def trigger_now_async(
        self,
        schedule_id: str,
        *,
        trigger: str = "manual",
        idem_suffix: str = "",
        now: float | None = None,
    ) -> dict[str, Any]:
        ts = time.time() if now is None else float(now)
        with self._state_lock():
            spec = self._load_schedules_unlocked().get(schedule_id)
            if spec is None:
                raise KeyError(f"Unknown schedule: {schedule_id}")
            run_id, idem, skip_rec = self._claim_execution_slot(
                spec, trigger=trigger, idem_suffix=idem_suffix, now=ts
            )
        if skip_rec is not None:
            return skip_rec.to_dict()
        rec = await self._run_claimed_async(spec, run_id=run_id, trigger=trigger, idem=idem, now=ts)
        return rec.to_dict()

    async def run_startup_triggers_async(self, *, now: float | None = None) -> list[dict[str, Any]]:
        ts = time.time() if now is None else float(now)
        claimed: list[tuple[ScheduleSpec, str, str, ScheduleRunRecord | None]] = []
        with self._state_lock():
            specs = [
                s
                for s in self._load_schedules_unlocked().values()
                if s.enabled and s.live_execution_approved and s.trigger_type == "startup"
            ]
            for spec in specs:
                run_id, idem, skip_rec = self._claim_execution_slot(
                    spec, trigger="startup", idem_suffix="boot", now=ts
                )
                claimed.append((spec, run_id, idem, skip_rec))
        results: list[dict[str, Any]] = []
        for spec, run_id, idem, skip_rec in claimed:
            if skip_rec is not None:
                results.append(skip_rec.to_dict())
            else:
                rec = await self._run_claimed_async(spec, run_id=run_id, trigger="startup", idem=idem, now=ts)
                results.append(rec.to_dict())
        return results

    async def emit_event_async(
        self, event_name: str, *, payload: dict[str, Any] | None = None, now: float | None = None
    ) -> list[dict[str, Any]]:
        ts = time.time() if now is None else float(now)
        clean_ev = (event_name or "").strip()
        key = str((payload or {}).get("event_id") or "")
        claimed: list[tuple[ScheduleSpec, str, str, ScheduleRunRecord | None]] = []
        with self._state_lock():
            specs = [
                s
                for s in self._load_schedules_unlocked().values()
                if s.enabled and s.live_execution_approved and s.trigger_type == "event" and s.event_name == clean_ev
            ]
            for spec in specs:
                run_id, idem, skip_rec = self._claim_execution_slot(
                    spec, trigger=f"event:{clean_ev}", idem_suffix=key, now=ts
                )
                claimed.append((spec, run_id, idem, skip_rec))
        results: list[dict[str, Any]] = []
        for spec, run_id, idem, skip_rec in claimed:
            if skip_rec is not None:
                results.append(skip_rec.to_dict())
            else:
                rec = await self._run_claimed_async(
                    spec, run_id=run_id, trigger=f"event:{clean_ev}", idem=idem, now=ts
                )
                results.append(rec.to_dict())
        return results

    def _spawn_inflight(
        self,
        spec: ScheduleSpec,
        *,
        run_id: str,
        trigger: str,
        idem: str,
        now: float,
    ) -> asyncio.Task[ScheduleRunRecord]:
        task = asyncio.create_task(
            self._run_claimed_async(spec, run_id=run_id, trigger=trigger, idem=idem, now=now)
        )
        self._inflight_tasks.add(task)
        task.add_done_callback(self._inflight_tasks.discard)
        return task

    async def tick_async(self, *, now: float | None = None, wait: bool = True) -> list[dict[str, Any]]:
        ts = time.time() if now is None else float(now)
        due = self._collect_due_runs(now=ts, reserve_slots=True)
        out: list[dict[str, Any]] = []
        tasks: list[asyncio.Task[ScheduleRunRecord]] = []
        for spec, _slot_tag, run_id, idem, skip_rec in due:
            if skip_rec is not None:
                out.append(skip_rec.to_dict())
            else:
                tasks.append(
                    self._spawn_inflight(
                        spec, run_id=run_id, trigger=spec.trigger_type, idem=idem, now=ts
                    )
                )
        if wait and tasks:
            recs = await asyncio.gather(*tasks, return_exceptions=False)
            out.extend(rec.to_dict() for rec in recs)
        return out

    def _dispatch_due_startup_nonblocking(self, *, now: float | None = None) -> None:
        ts = time.time() if now is None else float(now)
        claimed: list[tuple[ScheduleSpec, str, str]] = []
        with self._state_lock():
            specs = [
                s
                for s in self._load_schedules_unlocked().values()
                if s.enabled and s.live_execution_approved and s.trigger_type == "startup"
            ]
            for spec in specs:
                run_id, idem, skip_rec = self._claim_execution_slot(
                    spec, trigger="startup", idem_suffix="boot", now=ts
                )
                if skip_rec is None:
                    claimed.append((spec, run_id, idem))
        for spec, run_id, idem in claimed:
            self._spawn_inflight(spec, run_id=run_id, trigger="startup", idem=idem, now=ts)

    async def _run_startup_hook(self, startup_hook: Callable[[], Any] | None) -> None:
        if startup_hook is None:
            return
        try:
            hook_res = startup_hook()
            if inspect.isawaitable(hook_res):
                await hook_res
        except Exception:  # noqa: BLE001
            pass

    async def _run_background_loop(
        self,
        stop_event: asyncio.Event,
        interval: float,
        startup_hook: Callable[[], Any] | None,
    ) -> None:
        await self._run_startup_hook(startup_hook)
        self._dispatch_due_startup_nonblocking()
        while not stop_event.is_set():
            try:
                await self.tick_async(wait=False)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                pass
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                continue

    def start_background_loop(
        self,
        *,
        poll_interval: float = 1.0,
        startup_hook: Callable[[], Any] | None = None,
    ) -> asyncio.Task[None]:
        """Start the authoritative async scheduler loop on the active server event loop."""
        if self._bg_task is not None and not self._bg_task.done():
            return self._bg_task
        interval = max(0.05, float(poll_interval))
        stop_event = asyncio.Event()
        self._bg_stop_event = stop_event
        self._bg_task = asyncio.create_task(
            self._run_background_loop(stop_event, interval, startup_hook),
            name="mcp-automation-scheduler",
        )
        return self._bg_task

    async def stop_background_loop(self, *, timeout: float = 5.0) -> None:
        """Stop scheduler loop and cancel/await any still in-flight schedule tasks cleanly."""
        if self._bg_stop_event is not None:
            self._bg_stop_event.set()
        tasks_to_cancel: list[asyncio.Task[Any]] = []
        if self._bg_task is not None and not self._bg_task.done():
            self._bg_task.cancel()
            tasks_to_cancel.append(self._bg_task)
        for task in list(self._inflight_tasks):
            if not task.done():
                task.cancel()
                tasks_to_cancel.append(task)
        if tasks_to_cancel:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks_to_cancel, return_exceptions=True),
                    timeout=max(0.2, float(timeout)),
                )
            except asyncio.TimeoutError:
                pass
        self._bg_task = None
        self._bg_stop_event = None
        self._inflight_tasks.clear()
