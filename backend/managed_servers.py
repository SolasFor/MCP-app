"""Owner-configured development servers, tracked by live process handles.

No remote configuration, arbitrary arguments, PID-based termination, or
cross-client control. Profiles are local JSON data. The direct child is
managed only for this backend's lifetime; descendants are not a sandbox.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from pathlib import Path
from dataclasses import dataclass


@dataclass
class Job:
    client_id: str
    name: str
    process: subprocess.Popen


class ManagedServers:
    def __init__(self, path: Path):
        self.path = path
        self._jobs: dict[tuple[str, str], Job] = {}
        self._lock = threading.RLock()

    def _profiles(self) -> dict:
        if not self.path.exists():
            return {}
        with self.path.open(encoding="utf-8-sig") as file:
            raw = file.read(65537)
        if len(raw) > 65536:
            raise ValueError("Managed server configuration is too large")
        profiles = json.loads(raw)
        if not isinstance(profiles, dict) or len(profiles) > 32:
            raise ValueError("Invalid managed server configuration")
        return profiles

    def _launch_args(self, name: str) -> tuple[list[str], Path]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            raise ValueError("Invalid server name")
        entry = self._profiles().get(name)
        if not isinstance(entry, dict):
            raise ValueError("Unknown server profile")
        argv = entry.get("argv")
        cwd = entry.get("cwd")
        if (not isinstance(argv, list) or not argv or len(argv) > 64
                or any(not isinstance(v, str) or "\x00" in v for v in argv)
                or not isinstance(cwd, str)):
            raise ValueError("Invalid argv or cwd")
        executable = Path(argv[0])
        directory = Path(cwd)
        if not executable.is_absolute() or not executable.is_file():
            raise ValueError("Use an absolute executable file path")
        if os.name == "nt" and executable.suffix.lower() != ".exe":
            raise ValueError("Use a direct .exe rather than a shell script")
        if not directory.is_absolute() or not directory.is_dir():
            raise ValueError("Use an existing absolute working directory")
        return argv, directory

    @staticmethod
    def _state(job: Job) -> dict:
        code = job.process.poll()
        return {"name": job.name, "running": code is None, "exit_code": code}

    def list(self, client_id: str) -> list[dict]:
        with self._lock:
            names = set(self._profiles())
            names.update(name for owner, name in self._jobs if owner == client_id)
            return [
                self._state(self._jobs[(client_id, name)])
                if (client_id, name) in self._jobs
                else {"name": name, "running": False, "exit_code": None}
                for name in sorted(names)
            ]

    def start(self, client_id: str, name: str) -> dict:
        with self._lock:
            key = (client_id, name)
            existing = self._jobs.get(key)
            if existing and existing.process.poll() is None:
                return self._state(existing)
            if any(j.name == name and j.process.poll() is None
                   for j in self._jobs.values()):
                raise ValueError("Server already managed by another client")
            if len(self._jobs) >= 32 and key not in self._jobs:
                self._jobs = {k: j for k, j in self._jobs.items()
                              if j.process.poll() is None}
                if len(self._jobs) >= 32:
                    raise ValueError("Managed process limit reached")
            argv, cwd = self._launch_args(name)
            # Do not pass the backend's MCP secrets/settings to dev servers.
            env = {k: v for k, v in os.environ.items()
                   if not k.upper().startswith("MCP_")}
            proc = subprocess.Popen(
                argv, cwd=str(cwd), env=env, shell=False,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            job = Job(client_id, name, proc)
            self._jobs[key] = job
            return self._state(job)

    def stop(self, client_id: str, name: str) -> dict:
        with self._lock:
            job = self._jobs.get((client_id, name))
            if job is None:
                raise ValueError("No managed process for this client")
            if job.process.poll() is None:
                job.process.terminate()
                try:
                    job.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    job.process.kill()
                    job.process.wait(timeout=5)
            return self._state(job)

    def close(self) -> None:
        with self._lock:
            for client_id, name in list(self._jobs):
                try:
                    self.stop(client_id, name)
                except (OSError, subprocess.TimeoutExpired):
                    pass
