"""Out-of-process JSON-RPC 2.0 stdio worker host for MCP-app Extensions.

Note: Spawning a separate OS process isolates worker crashes, stdout/stderr, and
runtime environments, NOT untrusted arbitrary code executed under the same OS user.
"""
from __future__ import annotations

import json
import os
import queue
import runpy
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable

from app.core.logging_manager import configure_logging
from app.core.redaction import SecretRedactor
from app.platform import get_platform
from app.platform.base import ProcessIdentity, ProcessJobHandle
from backend.extensions.store import runtime_entrypoint_prefix


def run_extension_entrypoint(entrypoint: str) -> int:
    """Execute an extension entrypoint inside `MCPApp.exe --run-extension <path>`."""
    lm = configure_logging()
    lm.install_exception_hooks()
    script = Path(entrypoint).resolve()
    if not script.is_file():
        lm.error("extensions", f"Extension entrypoint not found: {script}", event_code="ext_missing")
        sys.stderr.write(f"Extension entrypoint not found: {script}\n")
        lm.shutdown(timeout=1.0)
        return 2
    lm.info("extensions", f"Running extension worker entrypoint: {script.name}", event_code="ext_worker_start")
    for folder in (str(script.parent), str(Path(__file__).resolve().parents[2])):
        if folder not in sys.path:
            sys.path.insert(0, folder)
    try:
        runpy.run_path(str(script), run_name="__main__")
        return 0
    except Exception as exc:  # noqa: BLE001
        lm.log_crash(type(exc), exc, exc.__traceback__, context=f"extension:{script.name}")
        raise
    finally:
        lm.shutdown(timeout=1.0)


class ExtensionProcessHost:
    """Manages one extension child process over newline-delimited JSON-RPC 2.0."""

    def __init__(
        self,
        *,
        extension_id: str,
        entrypoint: Path,
        data_dir: Path,
        declared_secrets: dict[str, str],
        on_log: Callable[[str], None],
        redactor: SecretRedactor | None = None,
    ) -> None:
        self.extension_id = extension_id
        self.entrypoint = Path(entrypoint).resolve()
        self.data_dir = Path(data_dir).resolve()
        self.declared_secrets = dict(declared_secrets)
        self._on_log = on_log
        self._redactor = redactor
        self._lock = threading.Lock()
        self._proc: subprocess.Popen[str] | None = None
        self._proc_identity: ProcessIdentity | None = None
        self._job: ProcessJobHandle | None = None
        self._pump_threads: list[threading.Thread] = []
        self._replies: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._req_id = 0
        self.restarts = 0
        self.last_error = ""

    @property
    def pid(self) -> int | None:
        proc = self._proc
        return proc.pid if proc is not None and proc.poll() is None else None

    def is_alive(self) -> bool:
        proc = self._proc
        return proc is not None and proc.poll() is None

    def has_crashed(self) -> bool:
        proc = self._proc
        return proc is not None and proc.poll() is not None and proc.returncode != 0

    def _scrubbed_env(self) -> dict[str, str]:
        keep = (
            "PATH",
            "SYSTEMROOT",
            "COMSPEC",
            "WINDIR",
            "TEMP",
            "TMP",
            "HOME",
            "USERPROFILE",
            "LANG",
            "LC_ALL",
            "PATHEXT",
        )
        env = {k: v for k, v in os.environ.items() if k.upper() in keep or k in keep}
        project_root = str(Path(__file__).resolve().parents[2])
        old_pp = os.environ.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{project_root}{os.pathsep}{old_pp}" if old_pp else project_root
        env["PYTHONUTF8"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        env["MCP_EXTENSION_ID"] = self.extension_id
        env["MCP_EXTENSION_DATA_DIR"] = str(self.data_dir)
        return env

    @staticmethod
    def _terminate_worker_processes(
        proc: subprocess.Popen[str] | None,
        job: ProcessJobHandle | None,
        identity: ProcessIdentity | None,
        adapter: Any,
    ) -> None:
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except (OSError, subprocess.TimeoutExpired):
                pass
        if job is not None:
            try:
                adapter.terminate_job(job, exit_code=1)
            except Exception:  # noqa: BLE001
                pass
        if identity is not None:
            try:
                adapter.terminate_process_tree(identity, grace_seconds=0.2)
            except Exception:  # noqa: BLE001
                pass
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=1.5)
            except (OSError, subprocess.TimeoutExpired):
                pass

    @staticmethod
    def _close_worker_io_and_job(
        proc: subprocess.Popen[str] | None,
        threads: list[threading.Thread],
        job: ProcessJobHandle | None,
        adapter: Any,
    ) -> None:
        if proc is not None:
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass
        cur_thread = threading.current_thread()
        for th in threads:
            if th is not cur_thread:
                th.join(timeout=0.5)
        if job is not None:
            try:
                adapter.close_job(job)
            except Exception:  # noqa: BLE001
                pass

    def _cleanup_proc_locked(
        self,
        proc: subprocess.Popen[str] | None,
        *,
        terminate_active: bool = True,
    ) -> None:
        """Terminate worker/tree if running and release all handles, pipes, threads, and OS job."""
        adapter = get_platform()
        job = self._job
        self._job = None
        identity = self._proc_identity
        self._proc_identity = None
        threads = list(self._pump_threads)
        self._pump_threads = []
        if self._proc is proc:
            self._proc = None

        if terminate_active:
            self._terminate_worker_processes(proc, job, identity, adapter)
        self._close_worker_io_and_job(proc, threads, job, adapter)

    def start(self, *, timeout_seconds: float = 10.0) -> dict[str, Any]:
        with self._lock:
            if self.is_alive():
                return {"already_running": True, "pid": self.pid}
            if self._proc is not None or self._job is not None:
                self._cleanup_proc_locked(self._proc, terminate_active=True)
                self.restarts += 1
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self._replies = queue.Queue()
            cmd = runtime_entrypoint_prefix(self.entrypoint)
            kwargs: dict[str, Any] = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "cwd": str(self.data_dir),
                "env": self._scrubbed_env(),
                "text": True,
                "encoding": "utf-8",
                "errors": "replace",
                "bufsize": 1,
            }
            if sys.platform == "win32":
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            else:
                kwargs["start_new_session"] = True
            proc: subprocess.Popen[str] | None = None
            try:
                proc = subprocess.Popen(cmd, **kwargs)
                self._proc = proc
                adapter = get_platform()
                try:
                    self._proc_identity = adapter.capture_process_identity(proc.pid)
                except Exception:  # noqa: BLE001
                    self._proc_identity = None
                job = adapter.create_job(name=f"ext-{self.extension_id}", kill_on_close=True)
                self._job = job
                if job is not None:
                    assigned = adapter.assign_process_to_job(job, proc.pid)
                    if assigned is False:
                        raise RuntimeError(
                            f"Failed to assign extension {self.extension_id!r} worker pid={proc.pid} to OS job"
                        )
                self._on_log(f"[runtime] started worker pid={proc.pid}")
                t_out = threading.Thread(target=self._pump_stdout, args=(proc,), daemon=True)
                t_err = threading.Thread(target=self._pump_stderr, args=(proc,), daemon=True)
                self._pump_threads = [t_out, t_err]
                t_out.start()
                t_err.start()
                init_res = self._rpc_locked(
                    "initialize",
                    {"data_dir": str(self.data_dir), "secrets": self.declared_secrets},
                    timeout_seconds=timeout_seconds,
                )
            except BaseException:
                self._cleanup_proc_locked(proc, terminate_active=True)
                raise
            self.last_error = ""
            return dict(init_res) if isinstance(init_res, dict) else {"result": init_res}

    def _pump_stdout(self, proc: subprocess.Popen[str]) -> None:
        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                text = line.strip()
                if not text:
                    continue
                try:
                    obj = json.loads(text)
                    if isinstance(obj, dict) and obj.get("jsonrpc") == "2.0":
                        self._replies.put(obj)
                        continue
                except json.JSONDecodeError:
                    pass
                self._on_log(text)
        except (OSError, ValueError):
            pass
        finally:
            self._replies.put(None)

    def _pump_stderr(self, proc: subprocess.Popen[str]) -> None:
        assert proc.stderr is not None
        try:
            for line in proc.stderr:
                text = line.rstrip("\r\n")
                if text:
                    if self._redactor is not None:
                        text = self._redactor.redact_text(text)
                    self._on_log(f"[stderr] {text}")
        except (OSError, ValueError):
            pass

    def _rpc_locked(self, method: str, params: dict[str, Any], *, timeout_seconds: float) -> Any:
        proc = self._proc
        if proc is None or proc.poll() is not None or proc.stdin is None:
            rc = proc.returncode if proc is not None else None
            self.last_error = f"Extension worker stopped (exit={rc})"
            raise RuntimeError(self.last_error)

        self._req_id += 1
        rid = self._req_id
        payload = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}, ensure_ascii=False)
        try:
            proc.stdin.write(payload + "\n")
            proc.stdin.flush()
        except OSError as exc:
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass
            self.last_error = f"Extension IPC write failed: {exc}"
            raise RuntimeError(self.last_error) from exc

        while True:
            try:
                msg = self._replies.get(timeout=timeout_seconds)
            except queue.Empty as exc:
                self.last_error = f"Extension RPC timeout after {timeout_seconds:.1f}s ({method})"
                raise TimeoutError(self.last_error) from exc
            if msg is None:
                try:
                    rc = proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    rc = proc.poll()
                self.last_error = f"Extension worker exited unexpectedly (exit={rc})"
                raise RuntimeError(self.last_error)
            if msg.get("id") != rid:
                continue
            if "error" in msg and msg["error"] is not None:
                err = msg["error"]
                message = str(err.get("message") or "Extension error") if isinstance(err, dict) else str(err)
                self.last_error = self._redactor.redact_text(message) if self._redactor else message
                raise RuntimeError(self.last_error)
            return msg.get("result")

    def request(self, method: str, params: dict[str, Any] | None = None, *, timeout_seconds: float = 15.0) -> Any:
        with self._lock:
            return self._rpc_locked(method, params or {}, timeout_seconds=timeout_seconds)

    def stop(self) -> None:
        with self._lock:
            proc = self._proc
            if proc is None and self._job is None:
                return
            if proc is not None and proc.poll() is None:
                try:
                    self._rpc_locked("shutdown", {}, timeout_seconds=2.0)
                except Exception:  # noqa: BLE001
                    pass
                try:
                    proc.wait(timeout=2.0)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            self._on_log("[runtime] stopped worker")
            self._cleanup_proc_locked(proc, terminate_active=True)
            self._replies = queue.Queue()
