"""Durable SQLite registry for background tasks with DPAPI/POSIX-keyed spec encryption."""
from __future__ import annotations

import json
import os
import secrets
import shutil
import sqlite3
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

from app.platform import get_platform
from backend.output_stream import OutputSpoolManager
from backend.tasks.models import (
    ALL_STATUSES,
    STATUS_CANCELLED,
    STATUS_INTERRUPTED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    TERMINAL_STATUSES,
    TaskRecord,
    TaskSpec,
)

_KEY_PREFIX_WIN = b"DPAPI1:"
_KEY_PREFIX_POSIX = b"RAW1:"


def _load_or_create_task_key(db_path: Path) -> bytes:
    platform = get_platform()
    key_path = db_path.with_suffix(".key")
    if key_path.exists():
        data = key_path.read_bytes()
        if sys.platform == "win32" and data.startswith(_KEY_PREFIX_WIN):
            return platform.dpapi_unprotect(data[len(_KEY_PREFIX_WIN) :])
        if sys.platform != "win32" and data.startswith(_KEY_PREFIX_POSIX):
            if key_path.stat().st_mode & 0o077:
                raise PermissionError("Task encryption key must not be group/world readable")
            return data[len(_KEY_PREFIX_POSIX) :]
        raise ValueError("Task encryption key format invalid for current platform")

    if db_path.exists() and db_path.stat().st_size > 0:
        raise FileNotFoundError("Task encryption key missing for existing database")

    key = Fernet.generate_key()
    stored = (
        _KEY_PREFIX_WIN + platform.dpapi_protect(key)
        if sys.platform == "win32"
        else _KEY_PREFIX_POSIX + key
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(stored)
    platform.restrict_path_acl(key_path, is_dir=False)
    return key


class TaskStore:
    """Durable SQLite + WAL task store with encrypted task payload specs."""

    def __init__(self, db_path: Path | str) -> None:
        self.path = Path(db_path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._platform = get_platform()
        self._platform.restrict_path_acl(self.path.parent, is_dir=True)
        self._cipher = Fernet(_load_or_create_task_key(self.path))
        self._apply_migrations()
        self._platform.restrict_path_acl(self.path, is_dir=False)

    @contextmanager
    def _db(self):
        conn = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            yield conn
            if conn.in_transaction:
                conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def _apply_migrations(self) -> None:
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations(
                    version INTEGER PRIMARY KEY,
                    applied_at REAL NOT NULL,
                    description TEXT NOT NULL
                )
                """
            )
            applied = {
                row[0] for row in db.execute("SELECT version FROM schema_migrations").fetchall()
            }
            if 1 not in applied:
                db.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS tasks(
                        task_id TEXT PRIMARY KEY,
                        owner_client_id TEXT NOT NULL,
                        profile TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        title TEXT NOT NULL,
                        status TEXT NOT NULL,
                        priority INTEGER NOT NULL DEFAULT 0,
                        idempotency_key TEXT NOT NULL DEFAULT '',
                        created_at REAL NOT NULL,
                        started_at REAL,
                        finished_at REAL,
                        timeout_seconds INTEGER NOT NULL,
                        exit_code INTEGER,
                        error TEXT NOT NULL DEFAULT '',
                        progress_percent INTEGER,
                        spool_run_id TEXT,
                        artifact_refs_json TEXT NOT NULL DEFAULT '[]',
                        parent_task_id TEXT,
                        cancel_requested INTEGER NOT NULL DEFAULT 0,
                        spec_encrypted BLOB NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_tasks_status_prio
                        ON tasks(status, priority DESC, created_at ASC);
                    CREATE INDEX IF NOT EXISTS idx_tasks_owner_created
                        ON tasks(owner_client_id, created_at DESC);
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_tasks_owner_idempotency
                        ON tasks(owner_client_id, idempotency_key)
                        WHERE idempotency_key != '';
                    """
                )
                db.execute(
                    "INSERT OR IGNORE INTO schema_migrations VALUES (?,?,?)",
                    (1, time.time(), "Initial durable tasks table"),
                )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> TaskRecord:
        try:
            refs = json.loads(row["artifact_refs_json"] or "[]")
        except ValueError:
            refs = []
        return TaskRecord(
            task_id=row["task_id"],
            owner_client_id=row["owner_client_id"],
            profile=row["profile"],
            kind=row["kind"],
            title=row["title"],
            status=row["status"],
            priority=int(row["priority"]),
            idempotency_key=row["idempotency_key"] or "",
            created_at=float(row["created_at"]),
            started_at=float(row["started_at"]) if row["started_at"] is not None else None,
            finished_at=float(row["finished_at"]) if row["finished_at"] is not None else None,
            timeout_seconds=int(row["timeout_seconds"]),
            exit_code=int(row["exit_code"]) if row["exit_code"] is not None else None,
            error=row["error"] or "",
            progress_percent=int(row["progress_percent"]) if row["progress_percent"] is not None else None,
            spool_run_id=row["spool_run_id"],
            artifact_refs=refs if isinstance(refs, list) else [],
            parent_task_id=row["parent_task_id"],
            cancel_requested=bool(row["cancel_requested"]),
        )

    def recover_interrupted(self, message: str = "Interrupted by server restart or host shutdown") -> int:
        """Mark prior queued/running tasks as interrupted (never auto-restart commands)."""
        now = time.time()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute(
                """
                UPDATE tasks
                SET status = ?, finished_at = ?, error = ?
                WHERE status IN (?, ?)
                """,
                (STATUS_INTERRUPTED, now, message, STATUS_QUEUED, STATUS_RUNNING),
            )
            return int(cur.rowcount or 0)

    def create_task(
        self,
        *,
        owner_client_id: str,
        profile: str,
        title: str,
        spec: TaskSpec,
        priority: int = 0,
        idempotency_key: str = "",
        parent_task_id: str | None = None,
        max_queued_per_client: int = 20,
    ) -> tuple[TaskRecord, bool]:
        """Insert a queued task, honoring per-owner idempotency_key and queue quotas."""
        spec.validate()
        clean_idem = (idempotency_key or "").strip()[:128]
        clamped_prio = max(-100, min(100, int(priority)))
        encrypted = self._cipher.encrypt(spec.to_json().encode("utf-8"))
        now = time.time()
        task_id = f"tsk_{secrets.token_hex(8)}"
        spool_run_id = task_id

        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if clean_idem:
                existing = db.execute(
                    "SELECT * FROM tasks WHERE owner_client_id=? AND idempotency_key=?",
                    (owner_client_id, clean_idem),
                ).fetchone()
                if existing is not None:
                    return self._row_to_record(existing), True

            queued_count = db.execute(
                "SELECT count(*) FROM tasks WHERE owner_client_id=? AND status IN (?, ?)",
                (owner_client_id, STATUS_QUEUED, STATUS_RUNNING),
            ).fetchone()[0]
            if queued_count >= max_queued_per_client:
                raise RuntimeError(
                    f"Client active/queued task quota exceeded ({max_queued_per_client})"
                )

            db.execute(
                """
                INSERT INTO tasks(
                    task_id, owner_client_id, profile, kind, title, status,
                    priority, idempotency_key, created_at, timeout_seconds,
                    spool_run_id, artifact_refs_json, parent_task_id, cancel_requested,
                    spec_encrypted
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    task_id,
                    owner_client_id,
                    profile,
                    spec.kind,
                    title[:160],
                    STATUS_QUEUED,
                    clamped_prio,
                    clean_idem,
                    now,
                    int(spec.timeout),
                    spool_run_id,
                    "[]",
                    parent_task_id,
                    0,
                    encrypted,
                ),
            )
            row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            assert row is not None
            return self._row_to_record(row), False

    def get_task(self, task_id: str) -> TaskRecord | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        return self._row_to_record(row) if row is not None else None

    def get_spec(self, task_id: str) -> TaskSpec | None:
        with self._db() as db:
            row = db.execute("SELECT spec_encrypted FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if row is None:
            return None
        decrypted = self._cipher.decrypt(bytes(row["spec_encrypted"])).decode("utf-8")
        return TaskSpec.from_json(decrypted)

    def list_tasks(
        self,
        *,
        owner_client_id: str | None = None,
        status: str | None = None,
        active_only: bool = False,
        history_only: bool = False,
        limit: int = 100,
    ) -> list[TaskRecord]:
        clauses: list[str] = []
        args: list[Any] = []
        if owner_client_id is not None:
            clauses.append("owner_client_id = ?")
            args.append(owner_client_id)
        if status and status in ALL_STATUSES:
            clauses.append("status = ?")
            args.append(status)
        if active_only:
            clauses.append("status IN (?, ?)")
            args.extend([STATUS_QUEUED, STATUS_RUNNING])
        elif history_only:
            placeholders = ",".join("?" for _ in TERMINAL_STATUSES)
            clauses.append(f"status IN ({placeholders})")
            args.extend(sorted(TERMINAL_STATUSES))

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        safe_limit = max(1, min(500, int(limit)))
        args.append(safe_limit)
        with self._db() as db:
            rows = db.execute(
                f"SELECT * FROM tasks {where} ORDER BY created_at DESC LIMIT ?",
                tuple(args),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def pop_next_runnable(
        self,
        *,
        max_global: int,
        max_per_client: int,
    ) -> tuple[TaskRecord, TaskSpec] | None:
        """Atomically claim the highest-priority queued task respecting global/per-client quotas."""
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            global_running = db.execute(
                "SELECT count(*) FROM tasks WHERE status=?", (STATUS_RUNNING,)
            ).fetchone()[0]
            if global_running >= max_global:
                return None

            row = db.execute(
                """
                SELECT q.*
                FROM tasks AS q
                WHERE q.status = ?
                  AND (
                      SELECT count(*) FROM tasks AS r
                      WHERE r.status = ? AND r.owner_client_id = q.owner_client_id
                  ) < ?
                ORDER BY q.priority DESC, q.created_at ASC
                LIMIT 1
                """,
                (STATUS_QUEUED, STATUS_RUNNING, max_per_client),
            ).fetchone()
            if row is None:
                return None

            now = time.time()
            db.execute(
                "UPDATE tasks SET status=?, started_at=? WHERE task_id=?",
                (STATUS_RUNNING, now, row["task_id"]),
            )
            claimed = db.execute("SELECT * FROM tasks WHERE task_id=?", (row["task_id"],)).fetchone()
            assert claimed is not None
            decrypted = self._cipher.decrypt(bytes(claimed["spec_encrypted"])).decode("utf-8")
            return self._row_to_record(claimed), TaskSpec.from_json(decrypted)

    def mark_finished(
        self,
        task_id: str,
        *,
        status: str,
        exit_code: int | None = None,
        error: str = "",
        progress_percent: int | None = None,
        artifact_refs: list[dict[str, Any]] | None = None,
    ) -> TaskRecord | None:
        if status not in TERMINAL_STATUSES:
            raise ValueError(f"Expected terminal task status, got {status!r}")
        now = time.time()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if existing is None:
                return None
            refs_json = (
                json.dumps(artifact_refs, ensure_ascii=False)
                if artifact_refs is not None
                else existing["artifact_refs_json"]
            )
            db.execute(
                """
                UPDATE tasks
                SET status=?, finished_at=?, exit_code=?, error=?,
                    progress_percent=?, artifact_refs_json=?
                WHERE task_id=?
                """,
                (
                    status,
                    now,
                    exit_code,
                    (error or "")[:1024],
                    progress_percent,
                    refs_json,
                    task_id,
                ),
            )
            updated = db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        return self._row_to_record(updated) if updated is not None else None

    def request_cancel(self, task_id: str, *, owner_client_id: str | None = None) -> TaskRecord | None:
        """Mark queued task cancelled immediately or flag running task for cancellation."""
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if row is None:
                return None
            if owner_client_id is not None and row["owner_client_id"] != owner_client_id:
                raise PermissionError("Task does not belong to this OAuth client")
            if row["status"] == STATUS_QUEUED:
                db.execute(
                    "UPDATE tasks SET status=?, finished_at=?, cancel_requested=1, error=? WHERE task_id=?",
                    (STATUS_CANCELLED, time.time(), "Cancelled before execution", task_id),
                )
            elif row["status"] == STATUS_RUNNING:
                db.execute("UPDATE tasks SET cancel_requested=1 WHERE task_id=?", (task_id,))
            updated = db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        return self._row_to_record(updated) if updated is not None else None

    def list_cancel_requested_running(self) -> list[TaskRecord]:
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM tasks WHERE status=? AND cancel_requested=1",
                (STATUS_RUNNING,),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def create_restart_task(
        self,
        task_id: str,
        *,
        owner_client_id: str | None = None,
        max_queued_per_client: int = 20,
    ) -> TaskRecord | None:
        """Explicitly enqueue a fresh task cloned from an existing terminal task."""
        old = self.get_task(task_id)
        if old is None:
            return None
        if owner_client_id is not None and old.owner_client_id != owner_client_id:
            raise PermissionError("Task does not belong to this OAuth client")
        if old.status not in TERMINAL_STATUSES:
            raise RuntimeError("Only completed/failed/cancelled/interrupted tasks can be restarted.")
        spec = self.get_spec(task_id)
        if spec is None:
            return None
        rec, _ = self.create_task(
            owner_client_id=old.owner_client_id,
            profile=old.profile,
            title=old.title,
            spec=spec,
            priority=old.priority,
            idempotency_key="",
            parent_task_id=old.task_id,
            max_queued_per_client=max_queued_per_client,
        )
        return rec

    def enforce_retention(
        self,
        *,
        max_tasks: int = 200,
        ttl_seconds: int = 7 * 86400,
        spool_manager: OutputSpoolManager | None = None,
        artifacts_dir: Path | None = None,
    ) -> int:
        """Remove expired or overflow terminal tasks along with their spool & artifact dirs."""
        cutoff = time.time() - max(1, int(ttl_seconds))
        placeholders = ",".join("?" for _ in TERMINAL_STATUSES)
        victims: list[tuple[str, str | None]] = []

        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                f"""
                SELECT task_id, spool_run_id, finished_at, created_at
                FROM tasks
                WHERE status IN ({placeholders})
                ORDER BY COALESCE(finished_at, created_at) ASC
                """,
                tuple(sorted(TERMINAL_STATUSES)),
            ).fetchall()

            keep_candidates: list[tuple[str, str | None]] = []
            for row in rows:
                ts = float(row["finished_at"] or row["created_at"])
                if ts < cutoff:
                    victims.append((row["task_id"], row["spool_run_id"]))
                else:
                    keep_candidates.append((row["task_id"], row["spool_run_id"]))

            overflow = len(keep_candidates) - max(0, int(max_tasks))
            if overflow > 0:
                victims.extend(keep_candidates[:overflow])

            if victims:
                db.executemany("DELETE FROM tasks WHERE task_id=?", [(tid,) for tid, _ in victims])

        for tid, run_id in victims:
            if spool_manager is not None and run_id:
                self._safe_rmtree_under(spool_manager.spool_dir, spool_manager.spool_dir / run_id)
            if artifacts_dir is not None:
                self._safe_rmtree_under(Path(artifacts_dir), Path(artifacts_dir) / tid)
        return len(victims)

    @staticmethod
    def _safe_rmtree_under(base_dir: Path, target_dir: Path) -> bool:
        """Delete target_dir ONLY when its resolved path is a strict child of base_dir."""
        try:
            root = Path(base_dir).expanduser().resolve()
            victim = Path(target_dir).expanduser().resolve()
            if victim == root or not victim.is_relative_to(root):
                return False
            if not victim.exists():
                return False
            shutil.rmtree(victim, ignore_errors=True)
            return not victim.exists()
        except OSError:
            return False

    @staticmethod
    def _inactive_filter_sql(
        *,
        task_ids: tuple[str, ...] | None = None,
        older_than_days: int | None = None,
        exclude_task_ids: tuple[str, ...] = (),
        exclude_run_ids: tuple[str, ...] = (),
    ) -> tuple[str, list[Any]]:
        placeholders = ",".join("?" for _ in TERMINAL_STATUSES)
        clauses = [f"status IN ({placeholders})"]
        args: list[Any] = list(sorted(TERMINAL_STATUSES))

        if task_ids is not None:
            id_ph = ",".join("?" for _ in task_ids)
            clauses.append(f"task_id IN ({id_ph})")
            args.extend(task_ids)
        if older_than_days is not None:
            days = max(0, int(older_than_days))
            cutoff = time.time() - days * 86400
            clauses.append("COALESCE(finished_at, started_at, created_at) <= ?")
            args.append(cutoff)
        if exclude_task_ids:
            ex_ph = ",".join("?" for _ in exclude_task_ids)
            clauses.append(f"task_id NOT IN ({ex_ph})")
            args.extend(exclude_task_ids)
        if exclude_run_ids:
            rx_ph = ",".join("?" for _ in exclude_run_ids)
            clauses.append(f"(spool_run_id IS NULL OR spool_run_id NOT IN ({rx_ph}))")
            args.extend(exclude_run_ids)
        return " AND ".join(clauses), args

    def count_purgeable_inactive(
        self,
        *,
        older_than_days: int | None = None,
        exclude_task_ids: tuple[str, ...] = (),
        exclude_run_ids: tuple[str, ...] = (),
    ) -> int:
        where_sql, args = self._inactive_filter_sql(
            older_than_days=older_than_days,
            exclude_task_ids=tuple(exclude_task_ids),
            exclude_run_ids=tuple(exclude_run_ids),
        )
        with self._db() as db:
            row = db.execute(f"SELECT count(*) FROM tasks WHERE {where_sql}", tuple(args)).fetchone()
        return int(row[0] or 0) if row else 0

    def delete_inactive_tasks(
        self,
        *,
        task_ids: list[str] | tuple[str, ...] | None = None,
        older_than_days: int | None = None,
        spool_manager: OutputSpoolManager | None = None,
        artifacts_dir: Path | None = None,
        exclude_task_ids: tuple[str, ...] = (),
        exclude_run_ids: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        """Transactionally remove terminal tasks plus strictly owned internal spool/artifact dirs.

        Refuses active states (queued/running/cancelling/live workers). Never deletes user files,
        workspaces, exported results, or security audit logs.
        """
        explicit_ids = tuple(str(t) for t in task_ids) if task_ids is not None else None
        if explicit_ids is not None and len(explicit_ids) == 0:
            return {"deleted_count": 0, "deleted_task_ids": [], "cleaned_dirs": 0}

        victims: list[tuple[str, str | None]] = []
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if explicit_ids is not None:
                ph = ",".join("?" for _ in explicit_ids)
                existing_rows = db.execute(
                    f"SELECT task_id, status, cancel_requested, spool_run_id FROM tasks WHERE task_id IN ({ph})",
                    explicit_ids,
                ).fetchall()
                for row in existing_rows:
                    tid = str(row["task_id"])
                    run_id = row["spool_run_id"]
                    st = str(row["status"])
                    if (
                        st not in TERMINAL_STATUSES
                        or tid in exclude_task_ids
                        or (run_id and run_id in exclude_run_ids)
                    ):
                        raise ValueError(f"Cannot delete active or cancelling task {tid!r} (status={st})")

            where_sql, args = self._inactive_filter_sql(
                task_ids=explicit_ids,
                older_than_days=older_than_days,
                exclude_task_ids=tuple(exclude_task_ids),
                exclude_run_ids=tuple(exclude_run_ids),
            )
            rows = db.execute(
                f"SELECT task_id, spool_run_id FROM tasks WHERE {where_sql}",
                tuple(args),
            ).fetchall()
            victims = [(str(r["task_id"]), r["spool_run_id"]) for r in rows]
            if victims:
                victim_ids = [tid for tid, _ in victims]
                v_ph = ",".join("?" for _ in victim_ids)
                # Clear dangling parent_task_id links on surviving tasks before deleting history.
                db.execute(
                    f"UPDATE tasks SET parent_task_id = NULL WHERE parent_task_id IN ({v_ph})",
                    tuple(victim_ids),
                )
                db.executemany("DELETE FROM tasks WHERE task_id=?", [(tid,) for tid in victim_ids])

        cleaned_dirs = 0
        for tid, run_id in victims:
            if spool_manager is not None and run_id:
                if self._safe_rmtree_under(spool_manager.spool_dir, spool_manager.spool_dir / run_id):
                    cleaned_dirs += 1
            if artifacts_dir is not None:
                if self._safe_rmtree_under(Path(artifacts_dir), Path(artifacts_dir) / tid):
                    cleaned_dirs += 1
        return {
            "deleted_count": len(victims),
            "deleted_task_ids": [tid for tid, _ in victims],
            "cleaned_dirs": cleaned_dirs,
        }
