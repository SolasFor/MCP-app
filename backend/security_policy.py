"""Fail-closed access controls for public MCP tools.

This is deliberately stdlib-only so it can be tested without the MCP SDK.
These are server-wide gates, NOT per-client authorization. OAuth scopes and
per-client consent must be added before exposing powerful tools to third parties.
"""
from __future__ import annotations

import os
import shlex
import shutil
from pathlib import Path, PureWindowsPath

SENSITIVE_NAMES = frozenset({
    ".env", ".git", ".ssh", ".aws", ".config", ".gnupg", ".kube",
    "token.json", "settings.json", "credentials.json", "secrets.json",
    "id_rsa", "id_ed25519", "known_hosts", "config.yml",
})
SENSITIVE_SUFFIXES = frozenset({".pem", ".key", ".pfx", ".p12", ".ppk"})
RESERVED_WIN_STEMS = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
})
MAX_WRITE_BYTES = 128 * 1024


def enabled(value: str | None) -> bool:
    """No surprising implicit opt-in: accept only explicit affirmative values."""
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def exact_allowlist(value: str | None) -> frozenset[str]:
    """Comma-separated exact entries, never a blanket '*' wildcard."""
    items = {entry.strip().casefold() for entry in (value or "").split(",") if entry.strip()}
    if any("*" in item or "?" in item for item in items):
        raise ValueError("Wildcards are not allowed in tool allowlists")
    return frozenset(items)


def _is_sensitive(part: str) -> bool:
    lowered = part.casefold()
    return lowered in SENSITIVE_NAMES or Path(lowered).suffix in SENSITIVE_SUFFIXES or lowered.startswith(".env.")


def _is_reserved_win_part(part: str) -> bool:
    return part.split(".", 1)[0].casefold() in RESERVED_WIN_STEMS


def workspace_path(root: Path, relative_path: str) -> Path:
    """Resolve a relative workspace path while excluding credentials and symlink escapes.

    Recheck the resolved path as well as the input path to prevent aliases to
    sensitive files. Do not pass this as a security boundary against concurrent
    malicious local filesystem mutation (TOCTOU).
    """
    if (
        not isinstance(relative_path, str)
        or not relative_path
        or "\x00" in relative_path
        or "\\x00" in relative_path
        or ":" in relative_path
    ):
        raise ValueError("A non-empty safe relative path without NUL or ADS stream is required")
    if "\\" in relative_path and os.name != "nt":
        raise ValueError("Backslash paths are not supported on this system")
    input_path = Path(relative_path)
    win_path = PureWindowsPath(relative_path)
    if input_path.is_absolute() or win_path.is_absolute() or bool(win_path.drive):
        raise ValueError("Absolute paths are forbidden")
    if any(
        part in (".", "..") or _is_sensitive(part) or _is_reserved_win_part(part)
        for part in input_path.parts
    ):
        raise ValueError("Path traversal, reserved device name, or credential file is forbidden")
    root = root.resolve()
    target = (root / input_path).resolve()
    if not target.is_relative_to(root):
        raise ValueError("Path escapes the configured workspace")
    if any(_is_sensitive(part) or _is_reserved_win_part(part) for part in target.relative_to(root).parts):
        raise ValueError("Access to credentials or hidden configuration is forbidden")
    return target


def allowed_ssh_host(host: str, allowed: frozenset[str]) -> bool:
    """Empty allowlist means deny everything, including configured SSH aliases."""
    return bool(host) and host.strip().casefold() in allowed


def parse_allowed_command(command: str, allowed: frozenset[str]) -> list[str]:
    """Parse an allowed executable without using a shell.

    A configured executable may still be dangerous: this gate is only available
    in an explicitly enabled administrator profile.
    """
    if not isinstance(command, str) or not command.strip() or any(c in command for c in ("\x00", "\n", "\r")):
        raise ValueError("Invalid command")
    if not allowed:
        raise ValueError("MCP_ALLOWED_EXECUTABLES is empty (deny by default)")
    try:
        argv = shlex.split(command, posix=os.name != "nt")
    except ValueError as exc:
        raise ValueError("Malformed command quoting") from exc
    if os.name == "nt":
        argv = [part[1:-1] if part.startswith('"') and part.endswith('"') else part for part in argv]
    if not argv or len(argv) > 32 or len(command) > 2048:
        raise ValueError("Too many arguments or command too long")
    executable = argv[0]
    if any(c in executable for c in ("/", "\\", ":")) or executable.casefold() not in allowed:
        raise ValueError("Executable is not explicitly allowed")
    resolved = shutil.which(executable)
    if not resolved or not Path(resolved).is_absolute():
        raise ValueError("Allowed executable was not found on a trusted absolute path")
    if os.name == "nt" and Path(resolved).suffix.casefold() != ".exe":
        raise ValueError("Only direct .exe executables are permitted on Windows")
    return [resolved, *argv[1:]]
