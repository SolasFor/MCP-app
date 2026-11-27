"""Strict Paramiko SSH & SFTP transport client (RejectPolicy always, path & quota guards)."""
from __future__ import annotations

import base64
import posixpath
import socket
import stat
import time
from pathlib import Path
from typing import Any

import paramiko

from app.core.reconnect import BackoffPolicy
from backend.remote.models import (
    DeviceProfile,
    normalize_posix_path,
    validate_remote_posix_path,
)
from backend.remote.store import DeviceStore

MAX_CMD_OUTPUT_BYTES = 32 * 1024


class SSHConnectionError(RuntimeError):
    """Raised when an SSH connection drops, times out, or fails transport I/O."""


class SSHConnectionManager:
    """Stateless-per-call strict SSH/SFTP wrapper enforcing known_hosts RejectPolicy."""

    def __init__(self, store: DeviceStore) -> None:
        self._store = store
        self._health_backoff = BackoffPolicy(base_seconds=0.25, max_seconds=1.5, max_attempts=2)

    def _open_client(self, device: DeviceProfile, *, timeout: float = 10.0) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        if not device.known_hosts_path:
            try:
                client.load_system_host_keys()
            except OSError:
                pass
        known_hosts = (
            Path(device.known_hosts_path).expanduser()
            if device.known_hosts_path
            else (Path.home() / ".ssh" / "known_hosts")
        )
        if known_hosts.is_file():
            client.load_host_keys(str(known_hosts))
        # Fail closed: never trust an unverified host when known_hosts is absent or unmatched.
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        password = self._store.resolve_secret_ref(device.password_ref) if device.password_ref else None
        passphrase = self._store.resolve_secret_ref(device.passphrase_ref) if device.passphrase_ref else None
        key_filename = str(Path(device.key_path).expanduser()) if (device.auth_method == "key" and device.key_path) else None
        allow_agent = device.auth_method != "password_ref"
        look_for_keys = device.auth_method == "agent"

        try:
            client.connect(
                hostname=device.host,
                port=device.port,
                username=device.username or None,
                password=password if device.auth_method == "password_ref" else None,
                key_filename=key_filename,
                passphrase=passphrase,
                allow_agent=allow_agent,
                look_for_keys=look_for_keys,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
            )
            return client
        except paramiko.BadHostKeyException as exc:
            client.close()
            raise PermissionError(
                f"SSH host key CHANGED for {device.host}:{device.port} (refusing connection)"
            ) from exc
        except paramiko.AuthenticationException as exc:
            client.close()
            raise PermissionError(f"SSH authentication failed for {device.host}:{device.port}") from exc
        except paramiko.SSHException as exc:
            client.close()
            msg = str(exc)
            if "not found in known_hosts" in msg.lower() or "reject" in msg.lower() or "unknown" in msg.lower():
                raise PermissionError(
                    f"SSH host key not trusted in known_hosts for {device.host}:{device.port}"
                ) from exc
            raise SSHConnectionError(f"SSH protocol error: {exc}") from exc
        except (OSError, socket.error) as exc:
            client.close()
            raise SSHConnectionError(f"SSH network error connecting to {device.host}:{device.port}: {exc}") from exc

    def run_command(
        self,
        device: DeviceProfile,
        command: str,
        *,
        timeout: int = 12,
    ) -> dict[str, Any]:
        bounded_timeout = max(1, min(int(timeout), 600))
        client = self._open_client(device, timeout=min(10.0, float(bounded_timeout)))
        try:
            _, stdout, _stderr = client.exec_command(command, timeout=bounded_timeout)
            chan = stdout.channel
            out_buf = bytearray()
            err_buf = bytearray()
            deadline = time.monotonic() + bounded_timeout
            while True:
                if time.monotonic() >= deadline:
                    chan.close()
                    raise TimeoutError(f"SSH command timed out after {bounded_timeout}s")
                progressed = False
                if chan.recv_ready():
                    chunk = chan.recv(16384)
                    out_buf.extend(chunk[: max(0, MAX_CMD_OUTPUT_BYTES - len(out_buf))])
                    progressed = True
                if chan.recv_stderr_ready():
                    chunk = chan.recv_stderr(16384)
                    err_buf.extend(chunk[: max(0, MAX_CMD_OUTPUT_BYTES - len(err_buf))])
                    progressed = True
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
                if chan.closed and not chan.recv_ready() and not chan.recv_stderr_ready():
                    raise SSHConnectionError(
                        "SSH channel closed unexpectedly; remote process completion could not be confirmed"
                    )
                if not progressed:
                    time.sleep(0.05)
            code = chan.recv_exit_status()
            if code < 0:
                raise SSHConnectionError(
                    "SSH connection lost before remote exit status arrived"
                )
            return {
                "exit_code": int(code),
                "stdout": out_buf.decode("utf-8", errors="replace"),
                "stderr": err_buf.decode("utf-8", errors="replace"),
            }
        except PermissionError:
            raise
        except (paramiko.SSHException, OSError, EOFError) as exc:
            raise SSHConnectionError(
                f"SSH transport interrupted ({type(exc).__name__}); remote process state is unconfirmed"
            ) from exc
        finally:
            client.close()

    def probe_health(self, device: DeviceProfile) -> dict[str, Any]:
        """Run bounded read-only health check with small backoff on transient socket failures."""
        t0 = time.monotonic()
        last_err: Exception | None = None
        for attempt in range(self._health_backoff.max_attempts):
            try:
                res = self.run_command(device, "uname -s -m", timeout=5)
                latency_ms = int((time.monotonic() - t0) * 1000)
                return {
                    "device_id": device.device_id,
                    "reachable": res["exit_code"] == 0,
                    "latency_ms": latency_ms,
                    "system": res["stdout"].strip(),
                    "stderr": res["stderr"].strip(),
                }
            except PermissionError:
                raise
            except (SSHConnectionError, TimeoutError) as exc:
                last_err = exc
                if attempt + 1 < self._health_backoff.max_attempts:
                    time.sleep(min(0.4, self._health_backoff.next_delay(attempt + 1)))
        assert last_err is not None
        raise last_err

    def _verify_sftp_canonical(
        self,
        sftp: paramiko.SFTPClient,
        clean_path: str,
        allowed_roots: tuple[str, ...],
        *,
        for_write: bool = False,
    ) -> str:
        allowed_norm = [normalize_posix_path(r) for r in allowed_roots]
        probe = posixpath.dirname(clean_path) if for_write else clean_path
        cur = probe
        tail_parts: list[str] = []
        while True:
            try:
                real_anc = normalize_posix_path(sftp.normalize(cur))
                break
            except IOError as exc:
                if cur == "/":
                    raise PermissionError(
                        f"Unable to canonicalize remote SFTP path ancestor for {clean_path!r}"
                    ) from exc
                leaf = posixpath.basename(cur)
                if leaf:
                    tail_parts.append(leaf)
                cur = posixpath.dirname(cur) or "/"
        real_probe = (
            normalize_posix_path(posixpath.join(real_anc, *reversed(tail_parts)))
            if tail_parts
            else real_anc
        )
        allowed = any(
            root == "/" or real_probe == root or real_probe.startswith(root.rstrip("/") + "/")
            for root in allowed_norm
        )
        if not allowed:
            raise PermissionError(f"Resolved remote symlink/path {real_probe!r} escapes allowed SFTP roots")
        return clean_path

    def sftp_list(self, device: DeviceProfile, remote_path: str) -> dict[str, Any]:
        clean = validate_remote_posix_path(remote_path, device.allowed_sftp_roots)
        client = self._open_client(device, timeout=10.0)
        sftp: paramiko.SFTPClient | None = None
        try:
            sftp = client.open_sftp()
            self._verify_sftp_canonical(sftp, clean, device.allowed_sftp_roots)
            entries = []
            for attr in sftp.listdir_attr(clean)[:250]:
                mode = attr.st_mode or 0
                kind = "symlink" if stat.S_ISLNK(mode) else ("dir" if stat.S_ISDIR(mode) else "file")
                entries.append({
                    "name": attr.filename,
                    "type": kind,
                    "size": int(attr.st_size or 0),
                    "mtime": int(attr.st_mtime or 0),
                })
            return {"device_id": device.device_id, "path": clean, "entries": entries}
        except PermissionError:
            raise
        except (paramiko.SSHException, OSError) as exc:
            raise SSHConnectionError(f"SFTP list failed: {exc}") from exc
        finally:
            if sftp is not None:
                sftp.close()
            client.close()

    def sftp_download(
        self,
        device: DeviceProfile,
        remote_path: str,
        *,
        as_base64: bool = False,
    ) -> dict[str, Any]:
        clean = validate_remote_posix_path(remote_path, device.allowed_sftp_roots)
        client = self._open_client(device, timeout=10.0)
        sftp: paramiko.SFTPClient | None = None
        try:
            sftp = client.open_sftp()
            self._verify_sftp_canonical(sftp, clean, device.allowed_sftp_roots)
            lstat_info = sftp.lstat(clean)
            if lstat_info.st_mode is not None and stat.S_ISLNK(lstat_info.st_mode):
                raise PermissionError(f"Refusing SFTP symlink target: {clean!r}")
            declared_size = int(lstat_info.st_size or 0)
            if declared_size > device.sftp_max_bytes:
                raise PermissionError(
                    f"Remote file ({declared_size} bytes) exceeds SFTP quota ({device.sftp_max_bytes} bytes)"
                )
            with sftp.open(clean, "rb") as fh:
                raw = fh.read(device.sftp_max_bytes + 1)
            if len(raw) > device.sftp_max_bytes:
                raise PermissionError("Remote file stream exceeded configured SFTP quota")
            return {
                "device_id": device.device_id,
                "path": clean,
                "size_bytes": len(raw),
                "encoding": "base64" if as_base64 else "utf-8",
                "content": base64.b64encode(raw).decode("ascii") if as_base64 else raw.decode("utf-8", errors="replace"),
            }
        except PermissionError:
            raise
        except (paramiko.SSHException, OSError) as exc:
            raise SSHConnectionError(f"SFTP download failed: {exc}") from exc
        finally:
            if sftp is not None:
                sftp.close()
            client.close()

    def sftp_upload(
        self,
        device: DeviceProfile,
        remote_path: str,
        data: bytes,
    ) -> dict[str, Any]:
        if len(data) > device.sftp_max_bytes:
            raise PermissionError(
                f"Upload payload ({len(data)} bytes) exceeds SFTP quota ({device.sftp_max_bytes} bytes)"
            )
        clean = validate_remote_posix_path(remote_path, device.allowed_sftp_roots)
        client = self._open_client(device, timeout=10.0)
        sftp: paramiko.SFTPClient | None = None
        try:
            sftp = client.open_sftp()
            self._verify_sftp_canonical(sftp, clean, device.allowed_sftp_roots, for_write=True)
            try:
                lst = sftp.lstat(clean)
                if lst.st_mode is not None and stat.S_ISLNK(lst.st_mode):
                    raise PermissionError(f"Refusing SFTP overwrite of symlink: {clean!r}")
            except IOError:
                pass
            with sftp.open(clean, "wb") as fh:
                fh.write(data)
            return {
                "device_id": device.device_id,
                "path": clean,
                "bytes_written": len(data),
            }
        except PermissionError:
            raise
        except (paramiko.SSHException, OSError) as exc:
            raise SSHConnectionError(f"SFTP upload failed: {exc}") from exc
        finally:
            if sftp is not None:
                sftp.close()
            client.close()
