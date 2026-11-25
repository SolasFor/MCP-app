"""Scheduler with 5-field cron, TZ/DST, misfire/concurrency policies, safe-only retry & permission recheck."""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.core.redaction import SecretRedactor
from app.paths import user_data_dir
from app.platform import get_platform

_OFFSET_RE = re.compile(r"^(?:UTC|GMT)?([+-])(\d{1,2}):?(\d{2})$", re.IGNORECASE)
_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")


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
        # Fallback cleanly if minimal Windows env has no tzdata package for this zone.
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
    dow = frozenset(0 if d == 7 else d for d in raw_dow)  # 0=Sunday .. 6=Saturday
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
        # Convert Python weekday (Mon=0..Sun=6) -> cron weekday (Sun=0..Sat=6)
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
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScheduleSpec:
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
            client_id=str(data.get("client_id") or "owner"),
            misfire_policy=str(data.get("misfire_policy") or "skip"),
            concurrency_policy=str(data.get("concurrency_policy") or "forbid"),
            safe_retry=bool(data.get("safe_retry", False)),
            max_retries=int(data.get("max_retries") or 0),
            idempotency_key=str(data.get("idempotency_key") or ""),
            enabled=bool(data.get("enabled", True)),
            paused_reason=str(data.get("paused_reason") or ""),
            last_run_at=float(data.get("last_run_at") or 0.0),
            next_run_at=float(data.get("next_run_at") or 0.0),
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
    """Thread-safe persistent scheduler enforcing permissions, idempotency, DST, misfire & concurrency."""

    def __init__(
        self,
        base_dir: Path | None = None,
        *,
        executor: Callable[[ScheduleSpec, str], Any] | None = None,
        permission_checker: Callable[[ScheduleSpec], tuple[bool, str]] | None = None,
        notifier: Callable[[str, str], None] | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self.base_dir = Path(base_dir) if base_dir is not None else (user_data_dir() / "automation")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        get_platform().restrict_path_acl(self.base_dir, is_dir=True)
        self.schedules_path = self.base_dir / "schedules.json"
        self.history_path = self.base_dir / "history.json"
        self._executor = executor
        self._permission_checker = permission_checker
        self._notifier = notifier
        self._redactor = redactor or SecretRedactor()
        self._lock = threading.RLock()
        self._active_ids: set[str] = set()
        self._seen_idempotency: deque[str] = deque(maxlen=500)
        self._notifications: deque[dict[str, Any]] = deque(maxlen=100)

    def _atomic_write_json(self, path: Path, payload: dict[str, Any]) -> None:
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
        get_platform().restrict_path_acl(path, is_dir=False)

    def _load_schedules_unlocked(self) -> dict[str, ScheduleSpec]:
        if not self.schedules_path.is_file():
            return {}
        try:
            raw = json.loads(self.schedules_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        items = raw.get("schedules") if isinstance(raw, dict) else {}
        out: dict[str, ScheduleSpec] = {}
        if isinstance(items, dict):
            for rec in items.values():
                if isinstance(rec, dict):
                    try:
                        sp = ScheduleSpec.from_dict(rec)
                        out[sp.schedule_id] = sp
                    except (ValueError, TypeError):
                        continue
        return out

    def _save_schedules_unlocked(self, items: dict[str, ScheduleSpec]) -> None:
        self._atomic_write_json(
            self.schedules_path,
            {"version": 1, "schedules": {k: v.to_dict() for k, v in sorted(items.items())}},
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
        self._atomic_write_json(self.history_path, {"version": 1, "runs": rows})

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
    def check_actor_can_mutate(*, actor_id: str, actor_profile: str) -> None:
        if actor_id != "owner" and actor_profile != "full":
            raise PermissionError("Modifying automation schedules requires owner or Full Access profile")

    def list_schedules(self) -> list[dict[str, Any]]:
        with self._lock:
            return [s.to_dict() for s in self._load_schedules_unlocked().values()]

    def list_history(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
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
        self.check_actor_can_mutate(actor_id=actor_id, actor_profile=actor_profile)
        ts = time.time() if now is None else float(now)
        if spec.enabled and spec.next_run_at <= 0.0:
            spec.next_run_at = self._compute_next_run(spec, ts)
        with self._lock:
            all_s = self._load_schedules_unlocked()
            all_s[spec.schedule_id] = spec
            self._save_schedules_unlocked(all_s)
        return spec.to_dict()

    def remove_schedule(
        self,
        schedule_id: str,
        *,
        actor_id: str = "owner",
        actor_profile: str = "full",
    ) -> bool:
        self.check_actor_can_mutate(actor_id=actor_id, actor_profile=actor_profile)
        with self._lock:
            all_s = self._load_schedules_unlocked()
            if schedule_id not in all_s:
                return False
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

    def trigger_now(
        self,
        schedule_id: str,
        *,
        trigger: str = "manual",
        idem_suffix: str = "",
        now: float | None = None,
    ) -> dict[str, Any]:
        ts = time.time() if now is None else float(now)
        with self._lock:
            all_s = self._load_schedules_unlocked()
            spec = all_s.get(schedule_id)
            if spec is None:
                raise KeyError(f"Unknown schedule: {schedule_id}")
        return self._execute_spec(spec, trigger=trigger, idem_suffix=idem_suffix, now=ts).to_dict()

    def run_startup_triggers(self, *, now: float | None = None) -> list[dict[str, Any]]:
        ts = time.time() if now is None else float(now)
        results: list[dict[str, Any]] = []
        with self._lock:
            specs = [s for s in self._load_schedules_unlocked().values() if s.enabled and s.trigger_type == "startup"]
        for spec in specs:
            results.append(self._execute_spec(spec, trigger="startup", idem_suffix="boot", now=ts).to_dict())
        return results

    def emit_event(self, event_name: str, *, payload: dict[str, Any] | None = None, now: float | None = None) -> list[dict[str, Any]]:
        ts = time.time() if now is None else float(now)
        clean_ev = (event_name or "").strip()
        results: list[dict[str, Any]] = []
        with self._lock:
            specs = [
                s
                for s in self._load_schedules_unlocked().values()
                if s.enabled and s.trigger_type == "event" and s.event_name == clean_ev
            ]
        for spec in specs:
            key = str((payload or {}).get("event_id") or "")
            results.append(self._execute_spec(spec, trigger=f"event:{clean_ev}", idem_suffix=key, now=ts).to_dict())
        return results

    def tick(self, *, now: float | None = None) -> list[dict[str, Any]]:
        """Evaluate all due cron/interval schedules handling DST, misfire, and concurrency."""
        ts = time.time() if now is None else float(now)
        due: list[tuple[ScheduleSpec, str]] = []
        with self._lock:
            all_s = self._load_schedules_unlocked()
            changed = False
            for spec in all_s.values():
                if not spec.enabled or spec.trigger_type not in ("cron", "interval"):
                    continue
                if spec.next_run_at <= 0.0:
                    spec.next_run_at = self._compute_next_run(spec, ts)
                    changed = True
                    continue
                if ts < spec.next_run_at:
                    continue
                # Misfire detection: overdue by > 90s (or > interval_seconds)
                overdue_grace = 90.0 if spec.trigger_type == "cron" else float(max(30, spec.interval_seconds))
                is_misfire = (ts - spec.next_run_at) > overdue_grace
                if is_misfire and spec.misfire_policy == "skip":
                    spec.next_run_at = self._compute_next_run(spec, ts)
                    changed = True
                    self._append_history_unlocked(
                        ScheduleRunRecord(
                            run_id=secrets.token_hex(6),
                            schedule_id=spec.schedule_id,
                            trigger="misfire_skip",
                            started_at=ts,
                            finished_at=ts,
                            status="skipped_misfire",
                        )
                    )
                    continue
                slot_tag = str(int(spec.next_run_at))
                spec.next_run_at = self._compute_next_run(spec, ts)
                changed = True
                due.append((spec, slot_tag))
            if changed:
                self._save_schedules_unlocked(all_s)

        out: list[dict[str, Any]] = []
        for spec, slot_tag in due:
            rec = self._execute_spec(spec, trigger=spec.trigger_type, idem_suffix=slot_tag, now=ts)
            out.append(rec.to_dict())
        return out

    def _execute_spec(
        self,
        spec: ScheduleSpec,
        *,
        trigger: str,
        idem_suffix: str,
        now: float,
    ) -> ScheduleRunRecord:
        run_id = secrets.token_hex(6)
        idem = f"{spec.schedule_id}:{spec.idempotency_key}:{idem_suffix}" if (spec.idempotency_key or idem_suffix) else ""
        with self._lock:
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
                return rec
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
                return rec
            self._active_ids.add(spec.schedule_id)
            if idem:
                self._seen_idempotency.append(idem)

        attempts = 0
        max_attempts = 1 + (spec.max_retries if spec.safe_retry else 0)
        last_err = ""
        try:
            while attempts < max_attempts:
                if self._permission_checker is not None:
                    allowed, reason = self._permission_checker(spec)
                    if not allowed:
                        with self._lock:
                            all_s = self._load_schedules_unlocked()
                            stored = all_s.get(spec.schedule_id)
                            if stored is not None:
                                stored.enabled = False
                                stored.paused_reason = reason or "Permission revoked"
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
                            error=reason or "Permission revoked",
                        )
                        with self._lock:
                            self._append_history_unlocked(rec)
                        self._notify("Schedule Paused", f"{spec.name}: {rec.error}")
                        return rec

                attempts += 1
                try:
                    out = (
                        self._executor(spec, idem)
                        if self._executor is not None
                        else {"executed": spec.tool_name, "arguments": spec.arguments}
                    )
                    summary = self._redactor.redact_text(json.dumps(out, ensure_ascii=False, default=str)[:500])
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
                    with self._lock:
                        all_s = self._load_schedules_unlocked()
                        if spec.schedule_id in all_s:
                            all_s[spec.schedule_id].last_run_at = rec.finished_at
                            self._save_schedules_unlocked(all_s)
                        self._append_history_unlocked(rec)
                    return rec
                except Exception as exc:  # noqa: BLE001
                    last_err = self._redactor.redact_text(str(exc)) or type(exc).__name__
                    if not spec.safe_retry or attempts >= max_attempts:
                        break
            rec = ScheduleRunRecord(
                run_id=run_id,
                schedule_id=spec.schedule_id,
                trigger=trigger,
                started_at=now,
                finished_at=time.time(),
                status="failed",
                idempotency_key=idem,
                attempts=attempts,
                error=last_err,
            )
            with self._lock:
                self._append_history_unlocked(rec)
            self._notify("Schedule Failed", f"{spec.name}: {last_err}")
            return rec
        finally:
            with self._lock:
                self._active_ids.discard(spec.schedule_id)
