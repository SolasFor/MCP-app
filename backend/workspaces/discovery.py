"""Bounded static read-only project discovery & proposal builders for Workspace Wizard (Stage N04).

Security invariants:
- Strictly static read-only inspection inside canonicalized user-selected directories.
- Zero subprocess execution, zero network calls, zero dependency installs, zero secret file reads.
- Every opened file is verified via path_security (canonical root, segment checks, O_NOFOLLOW,
  opened OS handle verification, S_ISREG, and bounded byte limits).
- Secrets/credentials embedded in URLs or scripts are scrubbed and blocked from command proposals.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import threading
import time
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Literal

from app.core.redaction import SecretRedactor
from backend.workspaces.compose_yaml import (
    ComposeStaticSummary,
    ComposeYamlError,
    parse_safe_compose_yaml,
    parse_safe_yaml_mapping,
)
from backend.workspaces.models import (
    COMMAND_NAME_RE,
    WORKSPACE_ID_RE,
    WorkspaceProfile,
    validate_workspace_id,
)
from backend.workspaces.path_security import (
    PathSecurityError,
    canonical_workspace_root,
    is_reparse_or_link,
    is_sensitive_segment,
    resolve_workspace_path,
    sha256_bytes,
    verify_opened_fd,
)

if TYPE_CHECKING:
    from backend.servers.models import ServerProfile

EXCLUDED_DISCOVERY_DIRS = frozenset({
    "node_modules",
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    ".venv-build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "build",
    "dist",
    "out",
    ".next",
    ".nuxt",
    ".turbo",
    "target",
    "vendor",
    "coverage",
    ".cache",
    ".idea",
    ".vscode",
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    "secrets",
})

_COMPOSE_FILENAMES = (
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
)
_LOCKFILE_PM = (
    ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"),
    ("bun.lockb", "bun"),
    ("bun.lock", "bun"),
    ("package-lock.json", "npm"),
)
_ALLOWED_PACKAGE_MANAGERS = frozenset({"npm", "pnpm", "yarn", "bun"})
_NEXT_CONFIG_FILES = ("next.config.js", "next.config.mjs", "next.config.cjs", "next.config.ts")
_VITE_CONFIG_FILES = ("vite.config.js", "vite.config.mjs", "vite.config.cjs", "vite.config.ts")
_VALID_PM_RE = re.compile(r"^(npm|pnpm|yarn|bun)(?:@|$)")
_URL_CREDS_RE = re.compile(r"(?i)([A-Za-z][A-Za-z0-9+.-]{1,20}://[^:/@\s\"']+:)[^@\s\"']+(@)")
_URL_USER_ONLY_RE = re.compile(r"(?i)([A-Za-z][A-Za-z0-9+.-]{1,20}://)[^/@\s\"']{12,}(@)")
_SECRET_SCRIPT_RE = re.compile(
    r"(?i)(?:"
    r"(?:api[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"secret[_-]?key|password|passwd|pwd|private[_-]?key)\s*[:=]\s*\S+"
    r"|authorization\s*:\s*(?:bearer|basic)\s+\S+"
    r"|\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|cfut_[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16})\b"
    r")"
)
_SCRIPT_PORT_RE = re.compile(r"(?:--port(?:=|\s+)|-p\s+)(\d{2,5})\b")
_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]{0,100})")
_LIFECYCLE_HOOK_NAMES = frozenset({
    "preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly",
})
_DEFAULT_REDACTOR = SecretRedactor()


class DiscoveryCancelledError(RuntimeError):
    """Raised when workspace discovery is cancelled via cancel_event."""


class ManifestDriftError(ValueError):
    """Raised when approved manifest files changed on disk before task/server execution."""


class WizardConflictError(ValueError):
    """Raised when committing a workspace/server collides with existing IDs or canonical roots."""


class WizardStalePlanError(ValueError):
    """Raised when registry state or root identity changed since the wizard preview."""


class _ManifestTooLargeError(ValueError):
    pass


@dataclass(frozen=True)
class DiscoveryLimits:
    """Strict resource bounds for static read-only workspace discovery."""

    max_depth: int = 3
    max_entries: int = 400
    max_manifest_bytes: int = 128 * 1024
    max_total_bytes: int = 1024 * 1024
    max_seconds: float = 5.0


@dataclass(frozen=True)
class DiagnosticItem:
    level: Literal["info", "warn", "error"]
    code: str
    message: str
    source: str = ""


@dataclass(frozen=True)
class CommandProposal:
    name: str
    command: str
    source: str
    selected: bool = True
    has_lifecycle_hooks: bool = False
    warning: str = ""


@dataclass(frozen=True)
class ServerProposal:
    name: str
    display_name: str
    template: str
    cwd: str
    executable: str
    entrypoint: str
    host: str = "127.0.0.1"
    port: int | None = None
    port_verified: bool = False
    source: str = ""
    extra_args: tuple[str, ...] = ()
    readiness_kind: str = "none"
    health_path: str = "/health"
    selected: bool = False
    manifest_digests: dict[str, str] = field(default_factory=dict)
    warning: str = ""


@dataclass(frozen=True)
class SubprojectCandidate:
    relative_path: str
    root_path: str
    name: str
    language: str
    confidence: str
    source: str


@dataclass(frozen=True)
class WorkspaceDiscoveryResult:
    root_path: str
    name: str
    suggested_id: str
    language: str
    stacks: tuple[str, ...] = ()
    confidence: Literal["high", "medium", "low", "unknown"] = "unknown"
    git_root: str = ""
    git_verified: bool = False
    python_venv: str = ""
    node_path: str = ""
    exclude_patterns: tuple[str, ...] = ()
    commands: tuple[CommandProposal, ...] = ()
    server_proposals: tuple[ServerProposal, ...] = ()
    subprojects: tuple[SubprojectCandidate, ...] = ()
    sources: tuple[str, ...] = ()
    diagnostics: tuple[DiagnosticItem, ...] = ()
    manifest_digests: dict[str, str] = field(default_factory=dict)
    root_identity: tuple[int, int] | None = None
    truncated: bool = False


@dataclass(frozen=True)
class WizardPlanSnapshot:
    state_fingerprint: str
    root_path: str
    root_identity: tuple[int, int] | None
    manifest_digests: dict[str, str]
    existing_workspace_ids: tuple[str, ...]
    existing_server_names: tuple[str, ...]


@dataclass(frozen=True)
class WizardAdditionPreview:
    profile: WorkspaceProfile
    new_servers: tuple[ServerProfile, ...]
    link_existing_servers: tuple[str, ...]
    conflicts: tuple[str, ...]
    nested_workspaces: tuple[str, ...]
    warnings: tuple[str, ...]
    effective_permissions: dict[str, Any]
    snapshot: WizardPlanSnapshot


def redact_discovery_text(text: str) -> str:
    """Scrub embedded URL credentials and known secret patterns from discovery output."""
    if not text:
        return text
    cleaned = _URL_CREDS_RE.sub(r"\1[REDACTED]\2", text)
    cleaned = _URL_USER_ONLY_RE.sub(r"\1[REDACTED]\2", cleaned)
    return _DEFAULT_REDACTOR.redact_text(cleaned)


def _command_has_secret_material(command: str) -> bool:
    if not command:
        return False
    if _URL_CREDS_RE.search(command) or _URL_USER_ONLY_RE.search(command):
        return True
    if _SECRET_SCRIPT_RE.search(command):
        return True
    return _DEFAULT_REDACTOR.redact_text(command) != command


def _validate_root_string(raw: str) -> None:
    if not raw or "\x00" in raw:
        raise PathSecurityError("Invalid workspace root path")
    if raw.startswith(("\\\\", "//", "\\??\\")):
        raise PathSecurityError("UNC or device paths are forbidden")
    rest = raw[2:] if (len(raw) >= 2 and raw[1] == ":" and raw[0].isalpha()) else raw
    if ":" in rest:
        raise PathSecurityError("NTFS Alternate Data Streams (:) are forbidden in workspace root")


def _is_remote_windows_drive(resolved: Path) -> bool:
    if sys.platform != "win32":
        return False
    windll = getattr(ctypes, "windll", None)
    if windll is None or not resolved.drive:
        return False
    try:
        return int(windll.kernel32.GetDriveTypeW(f"{resolved.drive}\\")) == 4
    except Exception:  # noqa: BLE001
        return False


def _banned_system_roots() -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = [
        (os.path.normcase(os.path.realpath(str(Path.home()))), "user home root"),
    ]
    for var in ("USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "SystemRoot", "WINDIR", "ProgramData"):
        val = os.environ.get(var, "").strip()
        if val:
            items.append((os.path.normcase(os.path.realpath(val)), var))
    if os.name == "nt":
        sys_drive = os.environ.get("SystemDrive", "C:").rstrip("\\/")
        for sub in ("Users", "Windows", "Program Files", "Program Files (x86)"):
            items.append((os.path.normcase(f"{sys_drive}\\{sub}"), f"{sys_drive}\\{sub}"))
    else:
        for banned in ("/etc", "/usr", "/var", "/proc", "/sys", "/dev", "/bin", "/sbin", "/lib", "/home", "/root"):
            items.append((banned, banned))
    return items


def is_forbidden_scan_root(path: Path) -> str | None:
    """Return reason string if `path` is too broad or system-critical for scanning."""
    resolved = Path(os.path.realpath(str(path)))
    if resolved == resolved.parent:
        return "Refusing filesystem root directory"
    if _is_remote_windows_drive(resolved):
        return "Refusing remote/network drive"
    norm = os.path.normcase(str(resolved))
    for banned_norm, label in _banned_system_roots():
        if norm == banned_norm:
            return f"Refusing broad system/profile root ({label})"
    return None


def _require_safe_root(root_path: str | Path) -> Path:
    raw = str(root_path or "").strip()
    _validate_root_string(raw)
    canonical = canonical_workspace_root(raw)
    reason = is_forbidden_scan_root(canonical)
    if reason:
        raise PathSecurityError(reason)
    return canonical


def compute_root_identity(root: Path) -> tuple[int, int] | None:
    try:
        st = os.lstat(root)
        return (int(st.st_dev), int(st.st_ino))
    except OSError:
        return None


def _safe_path_entry(raw_entry: str, proj_resolved: Path | None) -> str | None:
    part = raw_entry.strip().strip('"')
    if not part or part.startswith(("\\\\", "//")):
        return None
    p = Path(part)
    if not p.is_absolute() or is_reparse_or_link(p):
        return None
    try:
        canon = Path(os.path.realpath(str(p)))
    except OSError:
        return None
    if not canon.is_dir():
        return None
    if proj_resolved is not None and (canon == proj_resolved or canon.is_relative_to(proj_resolved)):
        return None
    return str(canon)


def _trusted_system_which(binary_name: str, *, project_root: Path | None = None) -> str:
    """Locate an executable on PATH strictly outside `project_root` without executing anything."""
    raw_path = os.environ.get("PATH", "")
    if not raw_path:
        return ""
    proj_resolved = Path(os.path.realpath(str(project_root))) if project_root is not None else None
    safe_dirs = [
        resolved
        for entry in raw_path.split(os.pathsep)
        if (resolved := _safe_path_entry(entry, proj_resolved)) is not None
    ]
    if not safe_dirs:
        return ""
    return shutil.which(binary_name, path=os.pathsep.join(safe_dirs)) or ""


def _check_budget(start_t: float, limits: DiscoveryLimits, cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise DiscoveryCancelledError("Workspace discovery cancelled")
    if (time.monotonic() - start_t) > limits.max_seconds:
        raise TimeoutError(f"Workspace discovery exceeded {limits.max_seconds:.1f}s limit")


def _safe_file_exists(root: Path, rel_path: str) -> bool:
    try:
        target = resolve_workspace_path(root, rel_path, allow_missing=False)
        return target.is_file() and not is_reparse_or_link(target)
    except (OSError, PathSecurityError, FileNotFoundError):
        return False


def _read_fd_bounded(fd: int, rel_path: str, limits: DiscoveryLimits, bytes_used: list[int]) -> bytes:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        return b""
    if st.st_size > limits.max_manifest_bytes:
        raise _ManifestTooLargeError(
            f"{rel_path} exceeds manifest size limit ({st.st_size} > {limits.max_manifest_bytes} bytes)"
        )
    if bytes_used[0] + st.st_size > limits.max_total_bytes:
        raise _ManifestTooLargeError(f"Total discovery read limit exceeded at {rel_path}")
    chunks: list[bytes] = []
    total = 0
    while chunk := os.read(fd, 65536):
        total += len(chunk)
        if total > limits.max_manifest_bytes or bytes_used[0] + total > limits.max_total_bytes:
            raise _ManifestTooLargeError(f"{rel_path} exceeded read budget")
        chunks.append(chunk)
    data = b"".join(chunks)
    bytes_used[0] += len(data)
    return data


def _read_manifest_bytes(
    root: Path,
    rel_path: str,
    *,
    limits: DiscoveryLimits,
    bytes_used: list[int],
) -> tuple[bytes, str] | None:
    try:
        target = resolve_workspace_path(root, rel_path, allow_missing=False)
    except (FileNotFoundError, PathSecurityError):
        return None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags)
    except OSError:
        return None
    try:
        verify_opened_fd(root, fd, target)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        data = _read_fd_bounded(fd, rel_path, limits, bytes_used)
        return data, sha256_bytes(data)
    finally:
        os.close(fd)


def _strict_json_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"Duplicate JSON key: {k!r}")
        out[k] = v
    return out


def _check_git_dir_at(cur: Path) -> tuple[str, bool, list[DiagnosticItem], bool]:
    dot_git = cur / ".git"
    if not os.path.lexists(dot_git):
        return "", False, [], False
    if is_reparse_or_link(dot_git):
        return "", False, [
            DiagnosticItem("warn", "GIT_REPARSE_REJECTED", ".git is a symlink/junction and was not trusted", ".git")
        ], True
    if dot_git.is_dir():
        if (dot_git / "HEAD").is_file() or (dot_git / "refs").is_dir():
            return str(cur), True, [], True
        return "", False, [DiagnosticItem("warn", "GIT_DIR_INCOMPLETE", ".git directory lacks HEAD/refs", ".git")], True
    if dot_git.is_file():
        return "", False, [
            DiagnosticItem(
                "warn",
                "GIT_WORKTREE_UNVERIFIED",
                ".git file (worktree/submodule gitdir) left unverified without reading external target",
                ".git",
            )
        ], True
    return "", False, [], True


def _inspect_git_boundary(
    root: Path,
    *,
    allow_parent_git_lookup: bool,
) -> tuple[str, bool, list[DiagnosticItem]]:
    cur: Path | None = root
    while cur is not None:
        g_root, g_ok, diags, decided = _check_git_dir_at(cur)
        if decided:
            return g_root, g_ok, diags
        if not allow_parent_git_lookup or cur.parent == cur:
            break
        cur = cur.parent
    return "", False, []


def _detect_safe_python_venv(root: Path) -> str:
    py_rel = Path("Scripts/python.exe") if os.name == "nt" else Path("bin/python")
    for venv_name in (".venv", "venv", ".venv-build"):
        cand = root / venv_name
        if not os.path.lexists(cand) or is_reparse_or_link(cand) or not cand.is_dir():
            continue
        py_bin = cand / py_rel
        if os.path.lexists(py_bin) and not is_reparse_or_link(py_bin.parent) and not is_reparse_or_link(py_bin):
            if py_bin.is_file():
                return str(cand)
    return ""


def _sanitize_server_id(raw: str, fallback: str = "app_server") -> str:
    from backend.servers.models import validate_server_name

    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw.strip()).strip("._-") or fallback
    clean = clean[:64]
    validate_server_name(clean)
    return clean


def suggest_unique_workspace_id(base_name: str, existing_ids: Iterable[str]) -> str:
    """Build a valid, unique workspace_id avoiding exact and case-insensitive collisions."""
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", (base_name or "").strip()).strip("._-") or "workspace"
    clean = clean[:64]
    if not WORKSPACE_ID_RE.fullmatch(clean):
        clean = "workspace"
    taken = {str(x).casefold() for x in existing_ids}
    if clean.casefold() not in taken:
        return validate_workspace_id(clean)
    for idx in range(2, 1000):
        suffix = f"_{idx}"
        cand = f"{clean[: 64 - len(suffix)]}{suffix}"
        if cand.casefold() not in taken:
            return validate_workspace_id(cand)
    return validate_workspace_id(f"ws_{int(time.time())}")


def _parse_req_packages(raw_bytes: bytes) -> set[str]:
    pkgs: set[str] = set()
    for line in raw_bytes.decode("utf-8", errors="replace").splitlines()[:500]:
        s = line.strip()
        if not s or s.startswith(("#", "-r", "--requirement", "-e", "--editable", "-c", "--constraint")) or "://" in s:
            continue
        m = _REQ_NAME_RE.match(s)
        if m:
            pkgs.add(m.group(1).lower().replace("-", "_"))
    return pkgs


def _read_pyproject_metadata(
    root: Path,
    limits: DiscoveryLimits,
    bytes_used: list[int],
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> tuple[set[str], bool]:
    deps: set[str] = set()
    has_pytest_cfg = False
    try:
        loaded = _read_manifest_bytes(root, "pyproject.toml", limits=limits, bytes_used=bytes_used)
        if loaded is None:
            return deps, False
        raw, sha = loaded
        digests["pyproject.toml"] = sha
        sources.append("pyproject.toml")
        doc = tomllib.loads(raw.decode("utf-8"))
        raw_proj = doc.get("project")
        proj_tbl: dict[str, Any] = raw_proj if isinstance(raw_proj, dict) else {}
        raw_deps = proj_tbl.get("dependencies")
        for dep in raw_deps if isinstance(raw_deps, list) else []:
            m = _REQ_NAME_RE.match(str(dep))
            if m:
                deps.add(m.group(1).lower().replace("-", "_"))
        raw_tool = doc.get("tool")
        tool_tbl: dict[str, Any] = raw_tool if isinstance(raw_tool, dict) else {}
        has_pytest_cfg = "pytest" in tool_tbl
    except _ManifestTooLargeError as exc:
        diagnostics.append(DiagnosticItem("error", "MANIFEST_TOO_LARGE", str(exc), "pyproject.toml"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, ValueError) as exc:
        diagnostics.append(DiagnosticItem("error", "MANIFEST_PARSE_ERROR", redact_discovery_text(str(exc)), "pyproject.toml"))
    return deps, has_pytest_cfg


def _read_requirements_deps(
    root: Path,
    limits: DiscoveryLimits,
    bytes_used: list[int],
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> set[str]:
    deps: set[str] = set()
    for req_name in ("requirements.txt", "requirements-dev.txt"):
        if not _safe_file_exists(root, req_name):
            continue
        try:
            loaded = _read_manifest_bytes(root, req_name, limits=limits, bytes_used=bytes_used)
            if loaded is not None:
                digests[req_name] = loaded[1]
                sources.append(req_name)
                deps.update(_parse_req_packages(loaded[0]))
        except _ManifestTooLargeError as exc:
            diagnostics.append(DiagnosticItem("error", "MANIFEST_TOO_LARGE", str(exc), req_name))
    return deps


def _build_python_servers(root: Path, deps: set[str], py_exe: str) -> list[ServerProposal]:
    exe_for_srv = py_exe or _trusted_system_which("python", project_root=root) or sys.executable
    if "fastapi" in deps or "uvicorn" in deps:
        entry = "main:app" if _safe_file_exists(root, "main.py") else ("app:app" if _safe_file_exists(root, "app.py") else "main:app")
        return [
            ServerProposal(
                name=_sanitize_server_id(f"{root.name}_api", "python_api"),
                display_name=f"{root.name} FastAPI",
                template="python_fastapi",
                cwd=str(root),
                executable=exe_for_srv,
                entrypoint=entry,
                port=8001,
                port_verified=False,
                source="pyproject.toml/requirements",
                readiness_kind="http",
                health_path="/health",
                selected=False,
            )
        ]
    if "flask" in deps:
        entry = "app:app" if _safe_file_exists(root, "app.py") else "main:app"
        return [
            ServerProposal(
                name=_sanitize_server_id(f"{root.name}_flask", "flask_app"),
                display_name=f"{root.name} Flask",
                template="python_flask",
                cwd=str(root),
                executable=exe_for_srv,
                entrypoint=entry,
                port=5000,
                port_verified=False,
                source="pyproject.toml/requirements",
                readiness_kind="tcp",
                health_path="/",
                selected=False,
            )
        ]
    return []


def _build_python_commands(
    root: Path,
    py_cmd: str,
    deps: set[str],
    has_pytest_cfg: bool,
) -> list[CommandProposal]:
    if _safe_file_exists(root, "tests"):
        return [
            CommandProposal(
                name="test",
                command=f'{py_cmd} -m unittest discover -s tests -p "test_*.py" -v',
                source="tests/ + python",
                selected=True,
            )
        ]
    if "pytest" in deps or has_pytest_cfg:
        return [
            CommandProposal(
                name="test",
                command=f"{py_cmd} -m pytest",
                source="pyproject.toml/requirements",
                selected=True,
            )
        ]
    return []


def _analyze_python_project(
    root: Path,
    *,
    limits: DiscoveryLimits,
    bytes_used: list[int],
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> tuple[bool, set[str], list[CommandProposal], list[ServerProposal], str]:
    py_venv = _detect_safe_python_venv(root)
    py_exe = str(Path(py_venv) / ("Scripts/python.exe" if os.name == "nt" else "bin/python")) if py_venv else ""
    py_cmd = f'"{py_exe}"' if py_exe else "python"

    has_pyproject = _safe_file_exists(root, "pyproject.toml")
    py_markers = ("pyproject.toml", "requirements.txt", "requirements-dev.txt", "Pipfile", "main.py", "app.py")
    detected = bool(py_venv) or any(_safe_file_exists(root, name) for name in py_markers)

    deps: set[str] = set()
    has_pytest_cfg = _safe_file_exists(root, "pytest.ini")
    if has_pyproject:
        p_deps, p_pytest = _read_pyproject_metadata(root, limits, bytes_used, digests, sources, diagnostics)
        deps.update(p_deps)
        has_pytest_cfg = has_pytest_cfg or p_pytest
    deps.update(_read_requirements_deps(root, limits, bytes_used, digests, sources, diagnostics))

    if not detected and not deps:
        return False, set(), [], [], py_venv

    cmds = _build_python_commands(root, py_cmd, deps, has_pytest_cfg)
    return True, deps, cmds, _build_python_servers(root, deps, py_exe), py_venv


def _extract_script_port(raw_val: str, current: int | None) -> int | None:
    if current is not None:
        return current
    m_port = _SCRIPT_PORT_RE.search(raw_val)
    if not m_port:
        return None
    p_num = int(m_port.group(1))
    return p_num if 1 <= p_num <= 65535 else None


def _process_single_script(
    k: str,
    raw_val: str,
    scripts: dict[str, Any],
    pm: str,
    diagnostics: list[DiagnosticItem],
) -> CommandProposal | None:
    if not COMMAND_NAME_RE.fullmatch(k):
        return None
    if _command_has_secret_material(raw_val):
        diagnostics.append(
            DiagnosticItem(
                "warn",
                "COMMAND_SECRET_FILTERED",
                f"Skipped script {k!r}: contains potential secret or credential material",
                f"package.json#scripts.{k}",
            )
        )
        return None
    has_hooks = (f"pre{k}" in scripts) or (f"post{k}" in scripts)
    return CommandProposal(
        name=k,
        command=f"{pm} {k}" if k in ("test", "start") else f"{pm} run {k}",
        source=f"package.json#scripts.{k}",
        selected=k in ("dev", "build", "test", "lint", "typecheck", "start"),
        has_lifecycle_hooks=has_hooks,
        warning="Runs pre/post lifecycle hooks on execution" if has_hooks else "",
    )


def _flag_lifecycle_hook_once(hook_flagged: bool, diagnostics: list[DiagnosticItem]) -> bool:
    if not hook_flagged:
        diagnostics.append(
            DiagnosticItem(
                "warn",
                "LIFECYCLE_HOOK_PRESENT",
                "package.json declares lifecycle hook scripts (pre*/post*/prepare) that run when package scripts execute",
                "package.json#scripts",
            )
        )
    return True


def _collect_node_scripts(
    scripts: dict[str, Any],
    pm: str,
    diagnostics: list[DiagnosticItem],
) -> tuple[list[CommandProposal], int | None]:
    cmds: list[CommandProposal] = []
    detected_port: int | None = None
    hook_flagged = False

    for k, raw_val in scripts.items():
        if not isinstance(k, str) or not isinstance(raw_val, str):
            continue
        if k in _LIFECYCLE_HOOK_NAMES or k.startswith(("pre", "post")):
            hook_flagged = _flag_lifecycle_hook_once(hook_flagged, diagnostics)
            continue
        if len(cmds) >= 16:
            break
        proposal = _process_single_script(k, raw_val, scripts, pm, diagnostics)
        if proposal is None:
            continue
        if k in ("dev", "start"):
            detected_port = _extract_script_port(raw_val, detected_port)
        cmds.append(proposal)
    return cmds, detected_port


def _resolve_package_manager(root: Path, pkg: dict[str, Any], sources: list[str]) -> str:
    raw_pm = str(pkg.get("packageManager") or "").strip()
    m_pm = _VALID_PM_RE.match(raw_pm)
    if m_pm and m_pm.group(1) in _ALLOWED_PACKAGE_MANAGERS:
        return m_pm.group(1)
    for lock_file, lock_pm in _LOCKFILE_PM:
        if _safe_file_exists(root, lock_file):
            sources.append(lock_file)
            return lock_pm
    return "npm"


def _build_node_servers(
    root: Path,
    *,
    node_exe: str,
    deps_all: dict[str, Any],
    has_next: bool,
    has_vite: bool,
    detected_port: int | None,
) -> list[ServerProposal]:
    if has_next:
        return [
            ServerProposal(
                name=_sanitize_server_id(f"{root.name}_next", "next_dev"),
                display_name=f"{root.name} Next.js",
                template="vite_next",
                cwd=str(root),
                executable=node_exe,
                entrypoint="next",
                port=detected_port or 3000,
                port_verified=False,
                source="package.json",
                readiness_kind="tcp",
                health_path="/",
                selected=False,
            )
        ]
    if has_vite:
        return [
            ServerProposal(
                name=_sanitize_server_id(f"{root.name}_vite", "vite_dev"),
                display_name=f"{root.name} Vite",
                template="vite_next",
                cwd=str(root),
                executable=node_exe,
                entrypoint="vite",
                port=detected_port or 5173,
                port_verified=False,
                source="package.json",
                readiness_kind="tcp",
                health_path="/",
                selected=False,
            )
        ]
    if "express" in deps_all:
        entry = next((cand for cand in ("server.js", "index.js", "app.js") if _safe_file_exists(root, cand)), "")
        if entry:
            return [
                ServerProposal(
                    name=_sanitize_server_id(f"{root.name}_express", "node_express"),
                    display_name=f"{root.name} Express",
                    template="node_express",
                    cwd=str(root),
                    executable=node_exe,
                    entrypoint=entry,
                    port=detected_port or 3000,
                    port_verified=False,
                    source="package.json",
                    readiness_kind="tcp",
                    health_path="/health",
                    selected=False,
                )
            ]
    return []


def _read_package_json_dict(
    root: Path,
    limits: DiscoveryLimits,
    bytes_used: list[int],
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> dict[str, Any] | None:
    try:
        loaded = _read_manifest_bytes(root, "package.json", limits=limits, bytes_used=bytes_used)
    except _ManifestTooLargeError as exc:
        diagnostics.append(DiagnosticItem("error", "MANIFEST_TOO_LARGE", str(exc), "package.json"))
        return None
    if loaded is None:
        return None
    digests["package.json"] = loaded[1]
    sources.append("package.json")
    try:
        pkg = json.loads(loaded[0].decode("utf-8"), object_pairs_hook=_strict_json_object_pairs)
    except (UnicodeDecodeError, ValueError) as exc:
        diagnostics.append(DiagnosticItem("error", "MANIFEST_PARSE_ERROR", redact_discovery_text(str(exc)), "package.json"))
        return None
    if not isinstance(pkg, dict):
        diagnostics.append(DiagnosticItem("error", "MANIFEST_PARSE_ERROR", "package.json must be a JSON object", "package.json"))
        return None
    return pkg


def _collect_deps_map(pkg: dict[str, Any]) -> dict[str, Any]:
    deps_all: dict[str, Any] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        sec = pkg.get(section)
        if isinstance(sec, dict):
            deps_all.update(sec)
    return deps_all


def _analyze_node_project(
    root: Path,
    *,
    limits: DiscoveryLimits,
    bytes_used: list[int],
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> tuple[bool, str, list[str], list[CommandProposal], list[ServerProposal], str]:
    node_path = _trusted_system_which("node.exe" if os.name == "nt" else "node", project_root=root)
    if not _safe_file_exists(root, "package.json"):
        return False, "", [], [], [], node_path
    pkg = _read_package_json_dict(root, limits, bytes_used, digests, sources, diagnostics)
    if pkg is None:
        return True, "javascript", ["javascript"], [], [], node_path

    pm = _resolve_package_manager(root, pkg, sources)
    deps_all = _collect_deps_map(pkg)
    has_ts = _safe_file_exists(root, "tsconfig.json") or ("typescript" in deps_all)
    language = "typescript" if has_ts else "javascript"
    stacks: list[str] = [language]
    has_next = ("next" in deps_all) or any(_safe_file_exists(root, f) for f in _NEXT_CONFIG_FILES)
    has_vite = ("vite" in deps_all) or any(_safe_file_exists(root, f) for f in _VITE_CONFIG_FILES)
    if has_next:
        stacks.append("nextjs")
    elif has_vite:
        stacks.append("vite")

    raw_scripts = pkg.get("scripts")
    scripts: dict[str, Any] = raw_scripts if isinstance(raw_scripts, dict) else {}
    cmds, detected_port = _collect_node_scripts(scripts, pm, diagnostics)
    servers = _build_node_servers(
        root,
        node_exe=node_path or "node",
        deps_all=deps_all,
        has_next=has_next,
        has_vite=has_vite,
        detected_port=detected_port,
    )
    return True, language, stacks, cmds, servers, node_path


def _analyze_compose_project(
    root: Path,
    *,
    limits: DiscoveryLimits,
    bytes_used: list[int],
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> tuple[bool, list[ServerProposal]]:
    compose_file = next((fname for fname in _COMPOSE_FILENAMES if _safe_file_exists(root, fname)), "")
    if not compose_file:
        return False, []
    try:
        loaded = _read_manifest_bytes(root, compose_file, limits=limits, bytes_used=bytes_used)
    except _ManifestTooLargeError as exc:
        diagnostics.append(DiagnosticItem("error", "MANIFEST_TOO_LARGE", str(exc), compose_file))
        return True, []
    if loaded is None:
        return False, []

    digests[compose_file] = loaded[1]
    sources.append(compose_file)
    try:
        summary: ComposeStaticSummary = parse_safe_compose_yaml(
            loaded[0].decode("utf-8"),
            source_file=compose_file,
            max_bytes=limits.max_manifest_bytes,
        )
    except (UnicodeDecodeError, ComposeYamlError) as exc:
        diagnostics.append(DiagnosticItem("error", "MANIFEST_PARSE_ERROR", redact_discovery_text(str(exc)), compose_file))
        return True, []

    for w in summary.warnings:
        diagnostics.append(DiagnosticItem("info", "COMPOSE_ENV_UNREAD", w, compose_file))
    if not summary.services:
        return True, []

    docker_exe = _trusted_system_which("docker.exe" if os.name == "nt" else "docker", project_root=root) or "docker"
    first_port = next((p for svc in summary.services for p in svc.ports), None)
    return True, [
        ServerProposal(
            name=_sanitize_server_id(f"{root.name}_compose", "compose_stack"),
            display_name=f"{root.name} Compose ({len(summary.services)} svc)",
            template="docker_compose",
            cwd=str(root),
            executable=docker_exe,
            entrypoint=compose_file,
            port=first_port,
            port_verified=False,
            source=compose_file,
            readiness_kind="tcp" if first_port else "none",
            health_path="/",
            selected=False,
        )
    ]


def _globs_from_package_json(root: Path, limits: DiscoveryLimits, bytes_used: list[int]) -> list[str]:
    if not _safe_file_exists(root, "package.json"):
        return []
    try:
        loaded = _read_manifest_bytes(root, "package.json", limits=limits, bytes_used=bytes_used)
        if loaded is None:
            return []
        pkg = json.loads(loaded[0].decode("utf-8"), object_pairs_hook=_strict_json_object_pairs)
        ws = pkg.get("workspaces") if isinstance(pkg, dict) else None
        if isinstance(ws, list):
            return [str(x) for x in ws]
        if isinstance(ws, dict) and isinstance(ws.get("packages"), list):
            return [str(x) for x in ws["packages"]]
    except Exception:  # noqa: BLE001
        pass
    return []


def _globs_from_pnpm_yaml(
    root: Path,
    limits: DiscoveryLimits,
    bytes_used: list[int],
    diagnostics: list[DiagnosticItem],
) -> list[str]:
    if not _safe_file_exists(root, "pnpm-workspace.yaml"):
        return []
    try:
        loaded = _read_manifest_bytes(root, "pnpm-workspace.yaml", limits=limits, bytes_used=bytes_used)
        if loaded is None:
            return []
        ym = parse_safe_yaml_mapping(loaded[0].decode("utf-8"), max_bytes=limits.max_manifest_bytes)
        pkgs = ym.get("packages")
        if isinstance(pkgs, list):
            return [str(x) for x in pkgs]
    except Exception as exc:  # noqa: BLE001
        diagnostics.append(DiagnosticItem("warn", "MANIFEST_PARSE_ERROR", redact_discovery_text(str(exc)), "pnpm-workspace.yaml"))
    return []


def _globs_from_pyproject(root: Path, limits: DiscoveryLimits, bytes_used: list[int]) -> list[str]:
    if not _safe_file_exists(root, "pyproject.toml"):
        return []
    try:
        loaded = _read_manifest_bytes(root, "pyproject.toml", limits=limits, bytes_used=bytes_used)
        if loaded is None:
            return []
        doc = tomllib.loads(loaded[0].decode("utf-8"))
        uv_ws = doc.get("tool", {}).get("uv", {}).get("workspace", {})
        if isinstance(uv_ws, dict) and isinstance(uv_ws.get("members"), list):
            return [str(x) for x in uv_ws["members"]]
    except Exception:  # noqa: BLE001
        pass
    return []


def _extract_workspace_globs(
    root: Path,
    *,
    limits: DiscoveryLimits,
    bytes_used: list[int],
    diagnostics: list[DiagnosticItem],
) -> list[str]:
    globs = [
        *_globs_from_package_json(root, limits, bytes_used),
        *_globs_from_pnpm_yaml(root, limits, bytes_used, diagnostics),
        *_globs_from_pyproject(root, limits, bytes_used),
    ]
    return globs[:24]


def _is_safe_workspace_glob(pattern: str) -> str | None:
    clean = pattern.strip().replace("\\", "/")
    if not clean or clean.startswith("!") or clean.startswith("/") or ":" in clean or "**" in clean:
        return None
    parts = PurePosixPath(clean).parts
    if any(part in ("..", ".") or is_sensitive_segment(part) or part in EXCLUDED_DISCOVERY_DIRS for part in parts):
        return None
    return clean.rstrip("/")


def _try_add_monorepo_match(
    root: Path,
    match: Path,
    seen_roots: set[str],
    *,
    limits: DiscoveryLimits,
    cancel_event: threading.Event | None,
) -> SubprojectCandidate | None:
    if is_reparse_or_link(match) or not match.is_dir():
        return None
    try:
        canon = Path(os.path.realpath(str(match), strict=True))
        if not canon.is_relative_to(root) or canon == root:
            return None
        rel_parts = canon.relative_to(root).parts
        rel = canon.relative_to(root).as_posix()
    except (OSError, ValueError):
        return None
    if rel in seen_roots or any(seg in EXCLUDED_DISCOVERY_DIRS or is_sensitive_segment(seg) for seg in rel_parts):
        return None
    seen_roots.add(rel)
    sub_res = analyze_workspace_directory(
        canon,
        limits=limits,
        cancel_event=cancel_event,
        allow_parent_git_lookup=False,
        include_subprojects=False,
    )
    return SubprojectCandidate(
        relative_path=rel,
        root_path=str(canon),
        name=sub_res.name,
        language=sub_res.language,
        confidence=sub_res.confidence,
        source=", ".join(sub_res.sources) or "monorepo",
    )


def _expand_safe_glob_pattern(
    root: Path,
    safe_pat: str,
    seen_roots: set[str],
    candidates: list[SubprojectCandidate],
    *,
    limits: DiscoveryLimits,
    start_t: float,
    cancel_event: threading.Event | None,
) -> bool:
    for match in sorted(root.glob(safe_pat))[:24]:
        _check_budget(start_t, limits, cancel_event)
        cand = _try_add_monorepo_match(root, match, seen_roots, limits=limits, cancel_event=cancel_event)
        if cand is None:
            continue
        candidates.append(cand)
        if len(candidates) >= 24:
            return True
    return False


def _discover_monorepo_subprojects(
    root: Path,
    *,
    limits: DiscoveryLimits,
    bytes_used: list[int],
    diagnostics: list[DiagnosticItem],
    start_t: float,
    cancel_event: threading.Event | None,
) -> tuple[SubprojectCandidate, ...]:
    raw_globs = _extract_workspace_globs(root, limits=limits, bytes_used=bytes_used, diagnostics=diagnostics)
    if not raw_globs:
        return ()
    seen_roots: set[str] = set()
    candidates: list[SubprojectCandidate] = []
    for raw_pat in raw_globs:
        _check_budget(start_t, limits, cancel_event)
        if raw_pat.strip().startswith("!"):
            continue
        safe_pat = _is_safe_workspace_glob(raw_pat)
        if safe_pat is None:
            diagnostics.append(DiagnosticItem("warn", "WORKSPACE_GLOB_REJECTED", f"Unsafe monorepo glob rejected: {raw_pat!r}"))
            continue
        if _expand_safe_glob_pattern(
            root, safe_pat, seen_roots, candidates, limits=limits, start_t=start_t, cancel_event=cancel_event
        ):
            break
    return tuple(candidates)


def _pick_primary_language(node_ok: bool, node_lang: str, py_ok: bool, stacks: list[str]) -> str:
    if node_ok:
        return node_lang
    if py_ok:
        return "python"
    for lang in ("rust", "go"):
        if lang in stacks:
            return lang
    return "generic"


def _select_language_and_confidence(
    *,
    node_ok: bool,
    node_lang: str,
    py_ok: bool,
    stacks: list[str],
    git_verified: bool,
    py_venv: str,
    digests: dict[str, str],
    commands: list[CommandProposal],
    server_proposals: list[ServerProposal],
    subprojects: tuple[SubprojectCandidate, ...],
    diagnostics: list[DiagnosticItem],
) -> tuple[str, Literal["high", "medium", "low", "unknown"]]:
    language = _pick_primary_language(node_ok, node_lang, py_ok, stacks)
    if digests and (commands or server_proposals or subprojects):
        return language, "high"
    if stacks or git_verified or py_venv:
        return language, "medium"
    if any(d.code.startswith("MANIFEST_") for d in diagnostics):
        return language, "low"
    return language, "unknown"


def analyze_workspace_directory(
    root_path: str | Path,
    *,
    limits: DiscoveryLimits | None = None,
    cancel_event: threading.Event | None = None,
    allow_parent_git_lookup: bool = False,
    include_subprojects: bool = True,
) -> WorkspaceDiscoveryResult:
    """Perform strictly bounded static read-only inspection of one project directory."""
    cfg = limits or DiscoveryLimits()
    start_t = time.monotonic()
    _check_budget(start_t, cfg, cancel_event)
    root = _require_safe_root(root_path)
    root_ident = compute_root_identity(root)

    bytes_used = [0]
    digests: dict[str, str] = {}
    sources: list[str] = []
    diagnostics: list[DiagnosticItem] = []

    git_root, git_verified, git_diags = _inspect_git_boundary(
        root, allow_parent_git_lookup=allow_parent_git_lookup
    )
    diagnostics.extend(git_diags)
    if git_verified:
        sources.append(".git")

    _check_budget(start_t, cfg, cancel_event)
    py_ok, _py_deps, py_cmds, py_srvs, py_venv = _analyze_python_project(
        root, limits=cfg, bytes_used=bytes_used, digests=digests, sources=sources, diagnostics=diagnostics
    )
    _check_budget(start_t, cfg, cancel_event)
    node_ok, node_lang, node_stacks, node_cmds, node_srvs, node_path = _analyze_node_project(
        root, limits=cfg, bytes_used=bytes_used, digests=digests, sources=sources, diagnostics=diagnostics
    )
    _check_budget(start_t, cfg, cancel_event)
    compose_ok, compose_srvs = _analyze_compose_project(
        root, limits=cfg, bytes_used=bytes_used, digests=digests, sources=sources, diagnostics=diagnostics
    )

    subprojects: tuple[SubprojectCandidate, ...] = ()
    if include_subprojects:
        subprojects = _discover_monorepo_subprojects(
            root, limits=cfg, bytes_used=bytes_used, diagnostics=diagnostics, start_t=start_t, cancel_event=cancel_event
        )

    stacks: list[str] = []
    if node_ok:
        stacks.extend(node_stacks)
    if py_ok:
        stacks.append("python")
    if compose_ok:
        stacks.append("docker_compose")
    for fname, stack_name in (("Cargo.toml", "rust"), ("go.mod", "go")):
        if _safe_file_exists(root, fname):
            stacks.append(stack_name)
            sources.append(fname)

    commands = _dedupe_commands([*node_cmds, *py_cmds])
    server_proposals = [
        ServerProposal(**{**srv.__dict__, "manifest_digests": dict(digests)})
        for srv in (*node_srvs, *py_srvs, *compose_srvs)
    ]
    language, confidence = _select_language_and_confidence(
        node_ok=node_ok,
        node_lang=node_lang,
        py_ok=py_ok,
        stacks=stacks,
        git_verified=git_verified,
        py_venv=py_venv,
        digests=digests,
        commands=commands,
        server_proposals=server_proposals,
        subprojects=subprojects,
        diagnostics=diagnostics,
    )

    return WorkspaceDiscoveryResult(
        root_path=str(root),
        name=root.name or "workspace",
        suggested_id=suggest_unique_workspace_id(root.name or "workspace", ()),
        language=language,
        stacks=tuple(dict.fromkeys(stacks)),
        confidence=confidence,
        git_root=git_root,
        git_verified=git_verified,
        python_venv=py_venv,
        node_path=node_path,
        exclude_patterns=tuple(sorted(EXCLUDED_DISCOVERY_DIRS & {"node_modules", ".git", ".venv", "__pycache__", "dist", "build"})),
        commands=tuple(commands),
        server_proposals=tuple(server_proposals),
        subprojects=subprojects,
        sources=tuple(dict.fromkeys(sources)),
        diagnostics=tuple(diagnostics),
        manifest_digests=digests,
        root_identity=root_ident,
        truncated=False,
    )


def _dedupe_commands(items: list[CommandProposal]) -> list[CommandProposal]:
    seen: set[str] = set()
    out: list[CommandProposal] = []
    for item in items:
        if item.name not in seen:
            seen.add(item.name)
            out.append(item)
    return out


def _has_project_marker(directory: Path) -> tuple[bool, str, str]:
    markers = (
        ("package.json", "javascript", "package.json"),
        ("pyproject.toml", "python", "pyproject.toml"),
        ("requirements.txt", "python", "requirements.txt"),
        ("compose.yaml", "docker_compose", "compose.yaml"),
        ("compose.yml", "docker_compose", "compose.yml"),
        ("docker-compose.yml", "docker_compose", "docker-compose.yml"),
        ("Cargo.toml", "rust", "Cargo.toml"),
        ("go.mod", "go", "go.mod"),
    )
    for fname, lang, src in markers:
        if _safe_file_exists(directory, fname):
            if fname == "package.json" and _safe_file_exists(directory, "tsconfig.json"):
                return True, "typescript", "package.json + tsconfig.json"
            return True, lang, src
    return False, "generic", ""


def _is_scannable_subdir(child: Path) -> bool:
    if is_reparse_or_link(child) or not child.is_dir():
        return False
    return child.name.casefold() not in EXCLUDED_DISCOVERY_DIRS and not is_sensitive_segment(child.name)


def _scan_children_bounded(
    root: Path,
    cur: Path,
    depth: int,
    depth_cap: int,
    cfg: DiscoveryLimits,
    start_t: float,
    cancel_event: threading.Event | None,
    found: list[SubprojectCandidate],
    seen_entries: list[int],
) -> None:
    if depth > depth_cap or seen_entries[0] >= cfg.max_entries or len(found) >= 50:
        return
    try:
        children = sorted(cur.iterdir(), key=lambda p: p.name.casefold())
    except OSError:
        return
    for child in children:
        _check_budget(start_t, cfg, cancel_event)
        seen_entries[0] += 1
        if seen_entries[0] > cfg.max_entries or len(found) >= 50:
            return
        if not _is_scannable_subdir(child):
            continue
        has_marker, lang, src = _has_project_marker(child)
        if has_marker:
            found.append(
                SubprojectCandidate(
                    relative_path=child.relative_to(root).as_posix(),
                    root_path=str(child),
                    name=child.name,
                    language=lang,
                    confidence="medium",
                    source=src,
                )
            )
        if depth < depth_cap:
            _scan_children_bounded(root, child, depth + 1, depth_cap, cfg, start_t, cancel_event, found, seen_entries)


def discover_projects_in_directory(
    parent_path: str | Path,
    *,
    max_depth: int = 2,
    limits: DiscoveryLimits | None = None,
    cancel_event: threading.Event | None = None,
) -> list[SubprojectCandidate]:
    """Bounded read-only scan of immediate subdirectories under a user-selected parent folder."""
    cfg = limits or DiscoveryLimits()
    start_t = time.monotonic()
    _check_budget(start_t, cfg, cancel_event)
    root = _require_safe_root(parent_path)
    depth_cap = max(1, min(int(max_depth), cfg.max_depth))
    found: list[SubprojectCandidate] = []
    _scan_children_bounded(root, root, 1, depth_cap, cfg, start_t, cancel_event, found, [0])
    return found


def verify_manifest_digests(root: Path, expected_digests: Mapping[str, str]) -> None:
    """Fail closed if any approved manifest file disappeared, became unsafe, or changed SHA-256."""
    if not expected_digests:
        return
    canon_root = canonical_workspace_root(root)
    budget = [0]
    limits = DiscoveryLimits()
    for rel, expected_sha in expected_digests.items():
        loaded = _read_manifest_bytes(canon_root, rel, limits=limits, bytes_used=budget)
        if loaded is None:
            raise ManifestDriftError(
                f"Approved manifest {rel!r} is missing or unreadable; re-approve workspace before running"
            )
        if loaded[1].lower() != str(expected_sha).lower():
            raise ManifestDriftError(
                f"Approved manifest {rel!r} changed on disk since approval; re-approve workspace before running"
            )


def compute_current_manifest_digests(root: Path, paths: Iterable[str]) -> dict[str, str]:
    """Recompute SHA-256 digests for approved manifest relative paths inside `root`."""
    canon_root = canonical_workspace_root(root)
    budget = [0]
    limits = DiscoveryLimits()
    out: dict[str, str] = {}
    for rel in paths:
        loaded = _read_manifest_bytes(canon_root, rel, limits=limits, bytes_used=budget)
        if loaded is not None:
            out[rel] = loaded[1]
    return out


def compute_registry_fingerprint(
    workspaces: Mapping[str, WorkspaceProfile],
    servers: Mapping[str, ServerProfile],
) -> str:
    """Deterministic fingerprint of current workspace and server registries for stale-plan checks."""
    payload = {
        "workspaces": {k: workspaces[k].to_dict() for k in sorted(workspaces)},
        "servers": {k: servers[k].to_dict() for k in sorted(servers)},
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
