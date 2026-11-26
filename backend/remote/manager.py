"""Fail-closed Remote Management orchestrator: devices, SSH jobs, SFTP, services & metrics."""
from __future__ import annotations

import base64
import secrets
import threading
import time
from collections import deque
from typing import Any

from app.core.redaction import SecretRedactor
from backend.remote.models import (
    DeviceProfile,
    RemoteJobRecord,
    contains_shell_metacharacters,
    validate_device_id,
    validate_service_name,
)
from backend.remote.ssh_client import SSHConnectionError, SSHConnectionManager
from backend.remote.store import DeviceStore


class RemoteManager:
    """Authorized controller for remote SSH/SFTP targets, metrics, services, and background jobs."""

    def __init__(
        self,
        store: DeviceStore | None = None,
        *,
        ssh_client: SSHConnectionManager | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self.store = store or DeviceStore()
        self._redactor = redactor or SecretRedactor()
        self.ssh = ssh_client or SSHConnectionManager(self.store)
        self._lock = threading.RLock()
        self._jobs: dict[str, RemoteJobRecord] = {}
        self._logs: dict[str, deque[str]] = {}
        self._register_secrets()

    def _register_secrets(self) -> None:
        for secret in self.store.collect_secret_values():
            self._redactor.register(secret)

    def _log(self, device_id: str, line: str) -> None:
        clean = self._redactor.redact_text(line)
        with self._lock:
            buf = self._logs.setdefault(device_id, deque(maxlen=250))
            buf.append(clean)

    def get_logs(self, device_id: str) -> list[str]:
        with self._lock:
            return list(self._logs.get(device_id, ()))

    def _authorize(
        self,
        device_id: str,
        *,
        client_id: str,
        client_profile: str,
        need_permission: str = "",
    ) -> DeviceProfile:
        clean_id = validate_device_id(device_id)
        dev = self.store.get(clean_id)
        if dev is None:
            raise KeyError(f"Unknown remote device: {clean_id}")
        if not dev.enabled:
            raise PermissionError(f"Device {clean_id!r} is disabled")
        if client_id != "owner":
            if client_profile == "safe":
                raise PermissionError("Safe OAuth profile cannot access remote devices")
            if dev.min_profile == "full" and client_profile != "full":
                raise PermissionError(f"Device {clean_id!r} requires Full Access OAuth profile")
            if dev.allowed_clients and client_id not in dev.allowed_clients:
                raise PermissionError(f"Client {client_id!r} is not allowed on device {clean_id!r}")
        if need_permission:
            allowed = getattr(dev.permissions, need_permission, False)
            if not allowed:
                raise PermissionError(
                    f"Device {clean_id!r} does not grant '{need_permission}' permission"
                )
        return dev

    @staticmethod
    def _validate_command_for_profile(device: DeviceProfile, command: str, *, client_id: str, client_profile: str) -> str:
        cmd = (command or "").strip()
        if not cmd:
            raise ValueError("Command must not be empty")
        if client_id != "owner" and client_profile != "full":
            if contains_shell_metacharacters(cmd):
                raise PermissionError("Shell metacharacters prohibited in allowlist profile")
            if not device.allowed_commands or cmd not in device.allowed_commands:
                raise PermissionError("Command is not in device allowed_commands allowlist")
        return cmd

    def list_devices(
        self,
        *,
        group: str = "",
        client_id: str = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        if client_id != "owner" and client_profile == "safe":
            raise PermissionError("Safe OAuth profile cannot list remote devices")
        grp = (group or "").strip().lower()
        rows: list[dict[str, Any]] = []
        for dev in self.store.load_all().values():
            if grp and dev.group.lower() != grp:
                continue
            if client_id != "owner":
                if dev.allowed_clients and client_id not in dev.allowed_clients:
                    continue
                if dev.min_profile == "full" and client_profile != "full":
                    continue
            d = dev.to_dict()
            d.pop("password_ref", None)
            d.pop("passphrase_ref", None)
            rows.append(d)
        return {"devices": rows}

    def device_info(
        self,
        device_id: str,
        *,
        client_id: str = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        dev = self._authorize(device_id, client_id=client_id, client_profile=client_profile)
        data = dev.to_dict()
        data["logs"] = self.get_logs(dev.device_id)
        return data

    def device_health(
        self,
        device_id: str,
        *,
        client_id: str = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        dev = self._authorize(device_id, client_id=client_id, client_profile=client_profile)
        try:
            res = self.ssh.probe_health(dev)
            self._log(dev.device_id, f"[health] ok latency={res['latency_ms']}ms")
            return res
        except Exception as exc:
            msg = self._redactor.redact_text(str(exc))
            self._log(dev.device_id, f"[health] failed: {msg}")
            raise

    def ssh_execute(
        self,
        device_id: str,
        command: str,
        *,
        timeout: int = 12,
        client_id: str = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        dev = self._authorize(
            device_id,
            client_id=client_id,
            client_profile=client_profile,
            need_permission="execute",
        )
        cmd = self._validate_command_for_profile(dev, command, client_id=client_id, client_profile=client_profile)
        res = self.ssh.run_command(dev, cmd, timeout=timeout)
        res["stdout"] = self._redactor.redact_text(res["stdout"])
        res["stderr"] = self._redactor.redact_text(res["stderr"])
        self._log(dev.device_id, f"[exec] client={client_id} exit={res['exit_code']}")
        return {"device_id": dev.device_id, **res}

    def ssh_task_start(
        self,
        device_id: str,
        command: str,
        *,
        timeout: int = 60,
        client_id: str = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        dev = self._authorize(
            device_id,
            client_id=client_id,
            client_profile=client_profile,
            need_permission="execute",
        )
        cmd = self._validate_command_for_profile(dev, command, client_id=client_id, client_profile=client_profile)
        job_id = secrets.token_hex(8)
        rec = RemoteJobRecord(
            job_id=job_id,
            device_id=dev.device_id,
            command_redacted=self._redactor.redact_text(cmd.split()[0] + " …") if " " in cmd else cmd,
            state="running",
            started_at=time.time(),
        )
        with self._lock:
            self._jobs[job_id] = rec

        def _worker() -> None:
            try:
                res = self.ssh.run_command(dev, cmd, timeout=timeout)
                with self._lock:
                    rec.exit_code = int(res["exit_code"])
                    rec.output = self._redactor.redact_text((res["stdout"] + "\n" + res["stderr"]).strip())
                    rec.state = "succeeded" if rec.exit_code == 0 else "failed"
                    rec.finished_at = time.time()
            except SSHConnectionError as exc:
                with self._lock:
                    rec.state = "disconnected"
                    rec.disconnect_note = (
                        f"{exc}. Remote process stop/resume cannot be confirmed after SSH disconnect."
                    )
                    rec.finished_at = time.time()
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    rec.state = "failed"
                    rec.output = self._redactor.redact_text(str(exc))
                    rec.finished_at = time.time()

        threading.Thread(target=_worker, daemon=True).start()
        return rec.to_dict()

    def job_status(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            rec = self._jobs.get(job_id)
            if rec is None:
                raise KeyError(f"Unknown remote job: {job_id}")
            return rec.to_dict()

    def sftp_list(
        self,
        device_id: str,
        path: str,
        *,
        client_id: str = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        dev = self._authorize(
            device_id, client_id=client_id, client_profile=client_profile, need_permission="sftp_read"
        )
        res = self.ssh.sftp_list(dev, path)
        self._log(dev.device_id, f"[sftp_list] path={res['path']} entries={len(res['entries'])}")
        return res

    def sftp_download(
        self,
        device_id: str,
        path: str,
        *,
        as_base64: bool = False,
        client_id: str = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        dev = self._authorize(
            device_id, client_id=client_id, client_profile=client_profile, need_permission="sftp_read"
        )
        res = self.ssh.sftp_download(dev, path, as_base64=as_base64)
        if not as_base64:
            res["content"] = self._redactor.redact_text(res["content"])
        self._log(dev.device_id, f"[sftp_download] path={res['path']} bytes={res['size_bytes']}")
        return res

    def sftp_upload(
        self,
        device_id: str,
        path: str,
        content: str,
        *,
        encoding: str = "utf-8",
        client_id: str = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        dev = self._authorize(
            device_id, client_id=client_id, client_profile=client_profile, need_permission="sftp_write"
        )
        raw = base64.b64decode(content) if encoding.lower() == "base64" else content.encode("utf-8")
        res = self.ssh.sftp_upload(dev, path, raw)
        self._log(dev.device_id, f"[sftp_upload] path={res['path']} bytes={res['bytes_written']}")
        return res

    def remote_metrics(
        self,
        device_id: str,
        *,
        client_id: str = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        dev = self._authorize(
            device_id, client_id=client_id, client_profile=client_profile, need_permission="metrics"
        )
        probe = (
            "sh -c 'uname -a; "
            "echo __UP__; cat /proc/uptime 2>/dev/null || uptime; "
            "echo __MEM__; head -n 5 /proc/meminfo 2>/dev/null || true; "
            "echo __DF__; df -kP / 2>/dev/null | tail -n 2 || true'"
        )
        res = self.ssh.run_command(dev, probe, timeout=8)
        self._log(dev.device_id, f"[metrics] exit={res['exit_code']}")
        return {
            "device_id": dev.device_id,
            "exit_code": res["exit_code"],
            "metrics_text": self._redactor.redact_text(res["stdout"].strip()),
        }

    def remote_service_list(
        self,
        device_id: str,
        *,
        client_id: str = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        dev = self._authorize(
            device_id, client_id=client_id, client_profile=client_profile, need_permission="service_control"
        )
        res = self.ssh.run_command(
            dev,
            "sh -c 'if command -v systemctl >/dev/null 2>&1; then systemctl list-units --type=service --no-pager --plain | head -n 40; else service --status-all 2>&1 | head -n 40; fi'",
            timeout=10,
        )
        return {
            "device_id": dev.device_id,
            "exit_code": res["exit_code"],
            "services_output": self._redactor.redact_text(res["stdout"].strip()),
        }

    def remote_service_action(
        self,
        device_id: str,
        service_name: str,
        action: str,
        *,
        client_id: str = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        if action not in ("start", "stop"):
            raise ValueError(f"Unsupported service action: {action!r}")
        dev = self._authorize(
            device_id, client_id=client_id, client_profile=client_profile, need_permission="service_control"
        )
        svc = validate_service_name(service_name)
        if client_id != "owner" and client_profile != "full":
            if not dev.allowed_services or svc not in dev.allowed_services:
                raise PermissionError(f"Service {svc!r} is not in allowed_services allowlist")
        # Never elevate via sudo automatically; invoke direct service manager with explicit user rights.
        res = self.ssh.run_command(dev, f"systemctl {action} {svc}", timeout=15)
        self._log(dev.device_id, f"[service] {action} {svc} exit={res['exit_code']}")
        return {
            "device_id": dev.device_id,
            "service": svc,
            "action": action,
            "exit_code": res["exit_code"],
            "output": self._redactor.redact_text((res["stdout"] + "\n" + res["stderr"]).strip()),
        }

    def close(self) -> None:
        with self._lock:
            self._jobs.clear()
