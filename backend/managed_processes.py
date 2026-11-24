"""Process handles for explicitly authorized Full Access clients.

Jobs are scoped to their OAuth client and the current server lifetime.
Use direct executable + argument list, not a detached shell. Output is
drained into bounded in-memory tails; plaintext is never written to audit.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

MAX_JOBS = 16
MAX_OUTPUT_BYTES = 32768


@dataclass
class Job:
    job_id: str
    client_id: str
    process: asyncio.subprocess.Process
    started: float
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    task: asyncio.Task | None = None
    stopping: bool = False

    def snapshot(self) -> dict:
        return {
            "job_id": self.job_id,
            "pid": self.process.pid,
            "state": "running" if self.process.returncode is None else "exited",
            "exit_code": self.process.returncode,
            "stdout_tail": self.stdout.decode("utf-8", errors="replace"),
            "stderr_tail": self.stderr.decode("utf-8", errors="replace"),
        }


async def _drain(stream, target: bytearray) -> None:
    if stream is None:
        return
    while chunk := await stream.read(4096):
        target.extend(chunk)
        if len(target) > MAX_OUTPUT_BYTES:
            del target[:-MAX_OUTPUT_BYTES]


class ManagedProcesses:
    def __init__(self):
        self.jobs: dict[str, Job] = {}

    async def start(
        self, client_id: str, argv: list[str], cwd: Path,
        *, still_authorized: Callable[[], bool],
        finished: Callable[[int | None, int], None],
    ) -> dict:
        if not argv or any(not isinstance(v, str) or "\x00" in v for v in argv):
            raise ValueError("Invalid executable or arguments")
        if not argv[0].strip():
            raise ValueError("Missing executable")
        if not still_authorized():
            raise PermissionError("Full access is no longer authorized")
        # Do not silently run more jobs than we can monitor. Completed entries
        # can be evicted; never replace a live process handle.
        for key, job in list(self.jobs.items()):
            if len(self.jobs) < MAX_JOBS:
                break
            if job.task is not None and job.task.done():
                del self.jobs[key]
        if len(self.jobs) >= MAX_JOBS:
            raise RuntimeError("Managed process capacity reached")
        # Keep a slot reserved across the async process creation.
        if getattr(self, "_starting", 0) + len(self.jobs) >= MAX_JOBS:
            raise RuntimeError("Managed process capacity reached")
        self._starting = getattr(self, "_starting", 0) + 1
        try:
            process = await asyncio.create_subprocess_exec(
                *argv, cwd=str(cwd), stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        finally:
            self._starting -= 1
        job = Job(secrets.token_hex(16), client_id, process, time.monotonic())
        self.jobs[job.job_id] = job
        job.task = asyncio.create_task(self._watch(job, still_authorized, finished))
        return job.snapshot()

    async def _watch(self, job, still_authorized, finished):
        readers = [
            asyncio.create_task(_drain(job.process.stdout, job.stdout)),
            asyncio.create_task(_drain(job.process.stderr, job.stderr)),
        ]
        waiter = asyncio.create_task(job.process.wait())
        try:
            while not waiter.done():
                if not still_authorized():
                    await self._terminate(job)
                await asyncio.wait({waiter}, timeout=1)
        finally:
            if job.process.returncode is None:
                await self._terminate(job)
            await waiter
            # A descendant may keep a pipe open after the direct process exits.
            # Do not hold the monitor indefinitely waiting for that pipe.
            _, pending = await asyncio.wait(readers, timeout=2)
            for task in pending:
                task.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
            finished(job.process.returncode, int((time.monotonic() - job.started) * 1000))

    def _owned(self, client_id: str, job_id: str) -> Job:
        job = self.jobs.get(job_id)
        if job is None or job.client_id != client_id:
            raise PermissionError("Unknown managed process for this client")
        return job

    def status(self, client_id: str, job_id: str) -> dict:
        return self._owned(client_id, job_id).snapshot()

    async def _terminate(self, job: Job) -> None:
        if job.process.returncode is not None or job.stopping:
            return
        job.stopping = True
        try:
            try:
                job.process.terminate()
            except ProcessLookupError:
                return
            try:
                await asyncio.wait_for(job.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                try:
                    job.process.kill()
                except ProcessLookupError:
                    pass
                await job.process.wait()
        finally:
            job.stopping = False

    async def stop(self, client_id: str, job_id: str) -> dict:
        job = self._owned(client_id, job_id)
        await self._terminate(job)
        if job.task is not None:
            await job.task
        return job.snapshot()

    async def close(self) -> None:
        await asyncio.gather(*(self._terminate(job) for job in self.jobs.values()), return_exceptions=True)
        await asyncio.gather(*(job.task for job in self.jobs.values() if job.task is not None), return_exceptions=True)
        self.jobs.clear()
