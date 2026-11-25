"""Localhost Paramiko SSH/SFTP test server fixture for Stage 10 integration tests."""
from __future__ import annotations

import os
import posixpath
import socket
import stat
import threading
import time
from pathlib import Path
from typing import Any

import paramiko


class _TestSFTPHandle(paramiko.SFTPHandle):
    def __init__(self, flags: int, file_obj: Any) -> None:
        super().__init__(flags)
        self._file = file_obj

    def read(self, offset: int, length: int) -> bytes:
        self._file.seek(offset)
        return self._file.read(length)

    def write(self, offset: int, data: bytes) -> int:
        self._file.seek(offset)
        self._file.write(data)
        self._file.flush()
        return paramiko.SFTP_OK

    def stat(self) -> paramiko.SFTPAttributes:
        return paramiko.SFTPAttributes.from_stat(os.fstat(self._file.fileno()))

    def close(self) -> None:
        try:
            self._file.close()
        finally:
            super().close()


class _TestSFTPServer(paramiko.SFTPServerInterface):
    def __init__(self, server: paramiko.ServerInterface, root_dir: Path) -> None:
        super().__init__(server)
        self.root = root_dir.resolve()

    def _resolve(self, path: str) -> Path:
        norm = posixpath.normpath("/" + (path or "/").lstrip("/"))
        if norm.startswith("/sandbox/"):
            rel = norm[len("/sandbox/"):]
            target = (self.root / rel).resolve()
        elif norm == "/sandbox":
            target = self.root
        elif norm == "/escape_link":
            target = self.root.parent
        else:
            rel = norm.lstrip("/")
            target = (self.root / rel).resolve()
        return target

    def canonicalize(self, path: str) -> str:
        norm = posixpath.normpath("/" + (path or "/").lstrip("/"))
        if norm == "/sandbox/escape_link" or norm.startswith("/sandbox/escape_link/"):
            return "/outside/forbidden"
        return norm

    def list_folder(self, path: str) -> list[paramiko.SFTPAttributes] | int:
        target = self._resolve(path)
        if not target.is_dir():
            return paramiko.SFTP_NO_SUCH_FILE
        out: list[paramiko.SFTPAttributes] = []
        for child in sorted(target.iterdir()):
            attr = paramiko.SFTPAttributes.from_stat(child.stat())
            attr.filename = child.name
            out.append(attr)
        return out

    def stat(self, path: str) -> paramiko.SFTPAttributes | int:
        target = self._resolve(path)
        if not target.exists():
            return paramiko.SFTP_NO_SUCH_FILE
        return paramiko.SFTPAttributes.from_stat(target.stat())

    def lstat(self, path: str) -> paramiko.SFTPAttributes | int:
        norm = posixpath.normpath("/" + (path or "/").lstrip("/"))
        if norm == "/sandbox/sym_secret.txt":
            attr = paramiko.SFTPAttributes()
            attr.st_mode = stat.S_IFLNK | 0o777
            attr.st_size = 12
            return attr
        return self.stat(path)

    def open(self, path: str, flags: int, attr: paramiko.SFTPAttributes) -> paramiko.SFTPHandle | int:
        target = self._resolve(path)
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
        if writing:
            target.parent.mkdir(parents=True, exist_ok=True)
            mode = "r+b" if target.exists() and not (flags & os.O_TRUNC) else "w+b"
            return _TestSFTPHandle(flags, target.open(mode))
        if not target.is_file():
            return paramiko.SFTP_NO_SUCH_FILE
        return _TestSFTPHandle(flags, target.open("rb"))


class _TestSSHInterface(paramiko.ServerInterface):
    def __init__(self, username: str, password: str, state: dict[str, Any]) -> None:
        self.username = username
        self.password = password
        self.state = state
        self.exec_requests: list[str] = []

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        if username == self.username and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        cmd_str = command.decode("utf-8", errors="replace")
        self.exec_requests.append(cmd_str)
        threading.Thread(target=self._handle_exec, args=(channel, cmd_str), daemon=True).start()
        return True

    def _handle_exec(self, channel: paramiko.Channel, cmd: str) -> None:
        # Allow Paramiko's transport thread to emit SSH_MSG_CHANNEL_SUCCESS after
        # check_channel_exec_request returns True before sending output or closing.
        time.sleep(0.03)
        try:
            if cmd.strip() == "uname -s -m":
                channel.sendall(b"Linux x86_64\n")
                channel.send_exit_status(0)
            elif cmd.strip() == "drop_connection":
                channel.sendall(b"partial...\n")
                time.sleep(0.05)
                channel.transport.close()  # type: ignore[union-attr]
                return
            elif cmd.strip() == "slow_job":
                time.sleep(0.15)
                channel.sendall(b"job-done\n")
                channel.send_exit_status(0)
            elif "systemctl start " in cmd:
                svc = cmd.strip().split()[-1]
                self.state["services"][svc] = "active"
                channel.sendall(f"started {svc}\n".encode("utf-8"))
                channel.send_exit_status(0)
            elif "systemctl stop " in cmd:
                svc = cmd.strip().split()[-1]
                self.state["services"][svc] = "inactive"
                channel.sendall(f"stopped {svc}\n".encode("utf-8"))
                channel.send_exit_status(0)
            elif "systemctl list-units" in cmd:
                lines = "".join(f"{k}.service loaded {v}\n" for k, v in sorted(self.state["services"].items()))
                channel.sendall(lines.encode("utf-8"))
                channel.send_exit_status(0)
            elif "__MEM__" in cmd:
                channel.sendall(b"Linux ci-host\n__UP__\n123.4 10.0\n__MEM__\nMemTotal: 8192000 kB\n__DF__\n/dev/sda1 1000 500 500 50% /\n")
                channel.send_exit_status(0)
            elif cmd.startswith("echo "):
                channel.sendall((cmd[5:] + "\n").encode("utf-8"))
                channel.send_exit_status(0)
            else:
                channel.sendall(f"ran:{cmd}\n".encode("utf-8"))
                channel.send_exit_status(0)
        finally:
            try:
                channel.close()
            except Exception:  # noqa: BLE001
                pass


class LocalSSHServer:
    """In-process localhost Paramiko SSH+SFTP server for deterministic security & E2E tests."""

    def __init__(self, sftp_root: Path, *, username: str = "ciuser", password: str = "cipass") -> None:
        self.sftp_root = Path(sftp_root)
        self.sftp_root.mkdir(parents=True, exist_ok=True)
        self.username = username
        self.password = password
        self.host_key = paramiko.RSAKey.generate(2048)
        self.state: dict[str, Any] = {"services": {"nginx": "inactive"}}
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.25)
        self.host = "127.0.0.1"
        self.port = int(self._sock.getsockname()[1])
        self._stop = threading.Event()
        self._transports: list[paramiko.Transport] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def rotate_host_key(self) -> None:
        self.host_key = paramiko.RSAKey.generate(2048)

    def write_known_hosts(self, path: Path) -> Path:
        line = f"[{self.host}]:{self.port} {self.host_key.get_name()} {self.host_key.get_base64()}\n"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(line, encoding="utf-8")
        return path

    def start(self) -> LocalSSHServer:
        self._thread.start()
        return self

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client_sock, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_conn, args=(client_sock,), daemon=True).start()

    def _handle_conn(self, sock: socket.socket) -> None:
        t = paramiko.Transport(sock)
        t.add_server_key(self.host_key)
        t.set_subsystem_handler("sftp", paramiko.SFTPServer, sftp_si=_TestSFTPServer, root_dir=self.sftp_root)
        iface = _TestSSHInterface(self.username, self.password, self.state)
        self._transports.append(t)
        try:
            t.start_server(server=iface)
        except Exception:  # noqa: BLE001
            t.close()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        for t in self._transports:
            try:
                t.close()
            except Exception:  # noqa: BLE001
                pass
        self._thread.join(timeout=2.0)

    def __enter__(self) -> LocalSSHServer:
        return self.start()

    def __exit__(self, *args: object) -> None:
        self.stop()
