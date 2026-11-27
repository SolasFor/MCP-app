"""Asynchronous durable Task Manager orchestrator: queue, quotas, tree cancel, artifacts."""
from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from app.core.atomic_io import atomic_write_json, try_init_private_dir
from app.core.redaction import SecretRedactor
from backend.output_stream import OutputSpoolManager
from backend.process_runner import CommandResult, ProcessRunner
from backend.tasks.models import (
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_SUCCEEDED,
    TERMINAL_STATUSES,
    TaskRecord,
    TaskSpec,
    summarize_spec_title,
)
from backend.tasks.store import TaskStore

CommandExecutorFn = Callable[[TaskRecord, TaskSpec], Awaitable[CommandResult | str]]
AuthRecheckFn = Callable[[TaskRecord, TaskSpec], None]


class TaskManager:
    """Runs queued tasks asynchronously outside HTTP request lifetimes with strict ownership."""

    def __init__(
        self,
        store: TaskStore,
        runner: ProcessRunner,
        *,
        artifacts_dir: Path | str,
        redactor: SecretRedactor | None = None,
        spool: OutputSpoolManager | None = None,
        auth_rechecker: AuthRecheckFn | None = None,
        command_executor: CommandExecutorFn | None = None,
        workspace_task_executor: CommandExecutorFn | None = None,
        max_global_concurrent: int = 4,
        max_per_client_concurrent: int = 2,
        max_queued_per_client: int = 20,
        retention_max_tasks: int = 200,
        retention_ttl_seconds: int = 7 * 86400,
        poll_interval_seconds: float = 0.25,
    ) -> None:
        self.store = store
        self.runner = runner
        self.spool = spool or runner.spool
        self.redactor = redactor or runner.redactor
        self.artifacts_dir = Path(artifacts_dir).expanduser().resolve()
        try_init_private_dir(self.artifacts_dir)

        self._auth_rechecker = auth_rechecker
        self._command_executor = command_executor
        self._workspace_task_executor = workspace_task_executor
        self.max_global_concurrent = max(1, int(max_global_concurrent))
        self.max_per_client_concurrent = max(1, int(max_per_client_concurrent))
        self.max_queued_per_client = max(1, int(max_queued_per_client))
        self.retention_max_tasks = max(1, int(retention_max_tasks))
        self.retention_ttl_seconds = max(1, int(retention_ttl_seconds))
        self._poll_interval = max(0.05, float(poll_interval_seconds))

        self._wake_event: asyncio.Event | None = None
        self._dispatch_task: asyncio.Task[None] | None = None
        self._cancel_task: asyncio.Task[None] | None = None
        self._workers: dict[str, asyncio.Task[None]] = {}
        self._stopped = False

    def ensure_started(self) -> None:
        """Start background dispatch and cancel-monitor loops on the active event loop."""
        self._stopped = False
        if self._wake_event is None:
            self._wake_event = asyncio.Event()
        if self._dispatch_task is None or self._dispatch_task.done():
            self._dispatch_task = asyncio.create_task(self._dispatch_loop(), name="task-dispatcher")
        if self._cancel_task is None or self._cancel_task.done():
            self._cancel_task = asyncio.create_task(self._cancel_loop(), name="task-cancel-watch")
        self._wake_event.set()

    def _wake(self) -> None:
        if self._wake_event is not None:
            self._wake_event.set()

    async def _dispatch_loop(self) -> None:
        while not self._stopped:
            while not self._stopped:
                claimed = self.store.pop_next_runnable(
                    max_global=self.max_global_concurrent,
                    max_per_client=self.max_per_client_concurrent,
                )
                if claimed is None:
                    break
                rec, spec = claimed
                worker = asyncio.create_task(self._run_worker(rec, spec), name=f"task-{rec.task_id}")
                self._workers[rec.task_id] = worker
                tid = rec.task_id

                def _cleanup(_task: asyncio.Task[None], task_id: str = tid) -> None:
                    self._workers.pop(task_id, None)

                worker.add_done_callback(_cleanup)

            assert self._wake_event is not None
            self._wake_event.clear()
            try:
                await asyncio.wait_for(self._wake_event.wait(), timeout=self._poll_interval)
            except asyncio.TimeoutError:
                pass

    async def _cancel_loop(self) -> None:
        while not self._stopped:
            try:
                for rec in self.store.list_cancel_requested_running():
                    if rec.spool_run_id:
                        self.runner.cancel_run(rec.spool_run_id)
                    worker = self._workers.get(rec.task_id)
                    if worker is not None and not worker.done() and not rec.spool_run_id:
                        worker.cancel()
            except Exception:
                pass
            await asyncio.sleep(self._poll_interval)

    async def _run_worker(self, rec: TaskRecord, spec: TaskSpec) -> None:
        try:
            if self._auth_rechecker is not None:
                try:
                    self._auth_rechecker(rec, spec)
                except PermissionError as exc:
                    self._finalize_with_result(
                        rec,
                        status=STATUS_FAILED,
                        exit_code=None,
                        error=f"Permission denied before dispatch: {exc}",
                        summary_text="",
                    )
                    return

            if spec.workspace_id and spec.workspace_command:
                if self._workspace_task_executor is not None:
                    res = await self._workspace_task_executor(rec, spec)
                elif self._command_executor is not None:
                    res = await self._command_executor(rec, spec)
                else:
                    raise PermissionError("Workspace task executor is unavailable")
            elif self._command_executor is None:
                raise RuntimeError("TaskManager has no command executor configured")
            else:
                res = await self._command_executor(rec, spec)
            latest = self.store.get_task(rec.task_id)
            was_cancel_flagged = bool(latest and latest.cancel_requested)

            if isinstance(res, CommandResult):
                if res.cancelled or was_cancel_flagged:
                    status = STATUS_CANCELLED
                    err = "Task cancelled"
                elif res.timed_out:
                    status = STATUS_FAILED
                    err = f"Timed out after {spec.timeout}s"
                elif res.exit_code in (0, None):
                    status = STATUS_SUCCEEDED
                    err = ""
                else:
                    status = STATUS_FAILED
                    err = f"Exited with code {res.exit_code}"
                summary = f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}".strip()
                self._finalize_with_result(
                    rec,
                    status=status,
                    exit_code=res.exit_code,
                    error=err,
                    summary_text=summary,
                    stdout_bytes=res.stdout_bytes,
                    stderr_bytes=res.stderr_bytes,
                )
            else:
                text = str(res)
                if was_cancel_flagged:
                    self._finalize_with_result(
                        rec, status=STATUS_CANCELLED, exit_code=None, error="Task cancelled", summary_text=text
                    )
                elif text.startswith("❌"):
                    self._finalize_with_result(
                        rec, status=STATUS_FAILED, exit_code=1, error=text, summary_text=text
                    )
                else:
                    self._finalize_with_result(
                        rec, status=STATUS_SUCCEEDED, exit_code=0, error="", summary_text=text
                    )
        except asyncio.CancelledError:
            self._finalize_with_result(
                rec,
                status=STATUS_CANCELLED,
                exit_code=None,
                error="Task cancelled",
                summary_text="",
            )
        except PermissionError as exc:
            self._finalize_with_result(
                rec,
                status=STATUS_FAILED,
                exit_code=None,
                error=str(exc),
                summary_text="",
            )
        except Exception as exc:
            self._finalize_with_result(
                rec,
                status=STATUS_FAILED,
                exit_code=None,
                error=f"{type(exc).__name__}: {exc}",
                summary_text="",
            )
        finally:
            self._wake()

    def _finalize_with_result(
        self,
        rec: TaskRecord,
        *,
        status: str,
        exit_code: int | None,
        error: str,
        summary_text: str,
        stdout_bytes: int = 0,
        stderr_bytes: int = 0,
    ) -> None:
        clean_err = self.redactor.redact_text(error) if error else ""
        clean_summary = self.redactor.redact_text(summary_text) if summary_text else ""
        task_art_dir = self.artifacts_dir / rec.task_id
        try_init_private_dir(task_art_dir)

        result_file = task_art_dir / "result.json"
        payload = {
            "task_id": rec.task_id,
            "status": status,
            "exit_code": exit_code,
            "error": clean_err,
            "stdout_bytes": stdout_bytes,
            "stderr_bytes": stderr_bytes,
            "output_preview": clean_summary[:16384],
            "recorded_at": time.time(),
        }
        atomic_write_json(result_file, payload, indent=2, restrict_acl=True)

        artifact_refs = [
            {
                "name": "result.json",
                "size_bytes": result_file.stat().st_size,
                "content_type": "application/json",
            }
        ]
        self.store.mark_finished(
            rec.task_id,
            status=status,
            exit_code=exit_code,
            error=clean_err,
            artifact_refs=artifact_refs,
        )
        self.store.enforce_retention(
            max_tasks=self.retention_max_tasks,
            ttl_seconds=self.retention_ttl_seconds,
            spool_manager=self.spool,
            artifacts_dir=self.artifacts_dir,
        )

    async def submit(
        self,
        *,
        owner_client_id: str,
        profile: str,
        spec: TaskSpec,
        priority: int = 0,
        idempotency_key: str = "",
        title: str = "",
    ) -> tuple[TaskRecord, bool]:
        self.ensure_started()
        resolved_title = (
            self.redactor.redact_text(title.strip())
            if title.strip()
            else summarize_spec_title(spec.kind, spec.command, spec.host, self.redactor)
        )
        rec, dedup = self.store.create_task(
            owner_client_id=owner_client_id,
            profile=profile,
            title=resolved_title,
            spec=spec,
            priority=priority,
            idempotency_key=idempotency_key,
            max_queued_per_client=self.max_queued_per_client,
        )
        self._wake()
        return rec, dedup

    def _require_owned_task(self, task_id: str, owner_client_id: str) -> TaskRecord:
        rec = self.store.get_task(task_id)
        if rec is None:
            raise KeyError(f"Unknown task: {task_id!r}")
        if rec.owner_client_id != owner_client_id:
            raise PermissionError("Task does not belong to this OAuth client")
        return rec

    def status_dict(self, task_id: str, *, owner_client_id: str) -> dict[str, Any]:
        rec = self._require_owned_task(task_id, owner_client_id)
        data = rec.to_public_dict(self.redactor)
        data["mcp_task"] = rec.to_mcp_task_dict(self.redactor)
        return data

    def list_dicts(
        self,
        *,
        owner_client_id: str,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        rows = self.store.list_tasks(owner_client_id=owner_client_id, status=status, limit=limit)
        return [r.to_public_dict(self.redactor) for r in rows]

    def read_output(
        self,
        task_id: str,
        *,
        owner_client_id: str,
        stream: str = "stdout",
        offset: int = 0,
        limit: int = 8000,
    ) -> dict[str, Any]:
        rec = self._require_owned_task(task_id, owner_client_id)
        chosen = "stderr" if stream == "stderr" else "stdout"
        if not rec.spool_run_id:
            return {
                "task_id": rec.task_id,
                "stream": chosen,
                "text": "",
                "offset": offset,
                "total_bytes": 0,
                "returned_bytes": 0,
                "has_more": False,
                "next_offset": offset,
                "truncated_by_quota": False,
            }
        page = self.spool.read_page(
            rec.spool_run_id,
            "stderr" if chosen == "stderr" else "stdout",
            offset=offset,
            limit=limit,
            redactor=self.redactor,
        )
        return {
            "task_id": rec.task_id,
            "stream": page.stream,
            "text": page.text,
            "offset": page.offset,
            "total_bytes": page.total_bytes,
            "returned_bytes": page.returned_bytes,
            "has_more": page.has_more,
            "next_offset": page.next_offset,
            "truncated_by_quota": page.truncated_by_quota,
        }

    def result_dict(self, task_id: str, *, owner_client_id: str) -> dict[str, Any]:
        rec = self._require_owned_task(task_id, owner_client_id)
        out = rec.to_public_dict(self.redactor)
        res_path = self.artifacts_dir / rec.task_id / "result.json"
        if res_path.is_file():
            try:
                loaded = json.loads(res_path.read_text(encoding="utf-8"))
                out["result"] = loaded
            except (OSError, ValueError):
                pass
        return out

    def cancel(self, task_id: str, *, owner_client_id: str) -> dict[str, Any]:
        rec = self.store.request_cancel(task_id, owner_client_id=owner_client_id)
        if rec is None:
            raise KeyError(f"Unknown task: {task_id!r}")
        if rec.spool_run_id:
            self.runner.cancel_run(rec.spool_run_id)
        self._wake()
        return rec.to_public_dict(self.redactor)

    async def restart(self, task_id: str, *, owner_client_id: str, new_profile: str | None = None) -> dict[str, Any]:
        self.ensure_started()
        old = self._require_owned_task(task_id, owner_client_id)
        spec = self.store.get_spec(task_id)
        if spec is None:
            raise KeyError(f"Missing spec for task: {task_id!r}")
        if old.status not in TERMINAL_STATUSES:
            raise RuntimeError("Only terminal tasks can be restarted.")
        rec, _ = self.store.create_task(
            owner_client_id=owner_client_id,
            profile=new_profile or old.profile,
            title=old.title,
            spec=spec,
            priority=old.priority,
            idempotency_key="",
            parent_task_id=old.task_id,
            max_queued_per_client=self.max_queued_per_client,
        )
        self._wake()
        return rec.to_public_dict(self.redactor)

    def read_artifacts(
        self,
        task_id: str,
        *,
        owner_client_id: str,
        artifact_name: str = "",
        offset: int = 0,
        limit: int = 16000,
    ) -> dict[str, Any]:
        rec = self._require_owned_task(task_id, owner_client_id)
        art_dir = (self.artifacts_dir / rec.task_id).resolve()
        if not artifact_name:
            return {"task_id": rec.task_id, "artifacts": list(rec.artifact_refs)}
        clean_name = Path(artifact_name).name
        target = (art_dir / clean_name).resolve()
        if target.parent != art_dir or not target.is_file():
            raise FileNotFoundError(f"Artifact not found: {clean_name!r}")
        safe_off = max(0, int(offset))
        safe_lim = max(1, min(65536, int(limit)))
        with target.open("rb") as fh:
            fh.seek(safe_off)
            raw = fh.read(safe_lim)
        text = self.redactor.redact_text(raw.decode("utf-8", errors="replace"))
        total = target.stat().st_size
        return {
            "task_id": rec.task_id,
            "name": clean_name,
            "offset": safe_off,
            "total_bytes": total,
            "has_more": safe_off + len(raw) < total,
            "content": text,
        }

    def active_task_and_run_ids(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Return task IDs with live worker tasks and run IDs with active processes."""
        worker_ids = tuple(
            tid for tid, task in self._workers.items() if task is not None and not task.done()
        )
        run_ids = tuple(self.runner.active_run_ids())
        return worker_ids, run_ids

    def count_purgeable_tasks(self, *, older_than_days: int | None = None) -> int:
        ex_tasks, ex_runs = self.active_task_and_run_ids()
        return self.store.count_purgeable_inactive(
            older_than_days=older_than_days,
            exclude_task_ids=ex_tasks,
            exclude_run_ids=ex_runs,
        )

    def delete_inactive_task(self, task_id: str) -> dict[str, Any]:
        ex_tasks, ex_runs = self.active_task_and_run_ids()
        result = self.store.delete_inactive_tasks(
            task_ids=[task_id],
            spool_manager=self.spool,
            artifacts_dir=self.artifacts_dir,
            exclude_task_ids=ex_tasks,
            exclude_run_ids=ex_runs,
        )
        self._log_task_event(
            "task_deleted",
            f"Deleted inactive task task_id={task_id} count={result['deleted_count']}",
        )
        return result

    def purge_inactive_tasks(self, *, older_than_days: int | None = None) -> dict[str, Any]:
        ex_tasks, ex_runs = self.active_task_and_run_ids()
        result = self.store.delete_inactive_tasks(
            older_than_days=older_than_days,
            spool_manager=self.spool,
            artifacts_dir=self.artifacts_dir,
            exclude_task_ids=ex_tasks,
            exclude_run_ids=ex_runs,
        )
        scope = f">{older_than_days}d" if older_than_days is not None else "all_inactive"
        self._log_task_event(
            "tasks_purged",
            f"Purged inactive tasks scope={scope} deleted={result['deleted_count']} cleaned_dirs={result['cleaned_dirs']}",
        )
        return result

    @staticmethod
    def _log_task_event(event_code: str, message: str) -> None:
        try:
            from app.core.logging_manager import get_logging_manager

            get_logging_manager().info("tasks", message, event_code=event_code)
        except Exception:  # noqa: BLE001
            pass

    async def close(self) -> None:
        self._stopped = True
        self._wake()
        for t in list(self._workers.values()):
            if not t.done():
                t.cancel()
        for bg_task in (self._dispatch_task, self._cancel_task):
            if bg_task is not None and not bg_task.done():
                bg_task.cancel()
        await asyncio.gather(
            *(t for t in (*self._workers.values(), self._dispatch_task, self._cancel_task) if t is not None),
            return_exceptions=True,
        )
