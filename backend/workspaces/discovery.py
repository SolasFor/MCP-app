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
import fnmatch
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
from collections import deque
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
from backend.workspaces.manifest_policy import (
    ManifestDriftError as ManifestDriftError,
    ManifestLimitError,
    collect_significant_manifest_digests,
    hash_regular_file_bounded,
    is_safe_regular_file,
    read_regular_file_bounded,
    verify_manifest_digests as verify_manifest_digests,
)
from backend.workspaces.models import (
    COMMAND_NAME_RE,
    WORKSPACE_ID_RE,
    WorkspaceProfile,
    validate_workspace_id,
)
from backend.workspaces.path_security import (
    PathSecurityError,
    _is_reserved_win_name,
    canonical_workspace_root,
    is_reparse_or_link,
    is_sensitive_segment,
    resolve_workspace_path,
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


@dataclass
class _DiscoveryBudget:
    """Shared bounded resource tracker across discovery, subprojects, and manifest hashing."""

    limits: DiscoveryLimits
    start_t: float
    cancel_event: threading.Event | None = None
    entries_seen: int = 0
    bytes_used: list[int] = field(default_factory=lambda: [0])
    truncated: bool = False
    diagnostics: list[DiagnosticItem] = field(default_factory=list)
    _limit_codes: set[str] = field(default_factory=set)

    def check(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise DiscoveryCancelledError("Workspace discovery cancelled")
        if (time.monotonic() - self.start_t) > self.limits.max_seconds:
            raise TimeoutError(f"Workspace discovery exceeded {self.limits.max_seconds:.1f}s limit")

    def mark_limit(self, code: str, message: str, source: str = "") -> None:
        self.truncated = True
        if code in self._limit_codes:
            return
        self._limit_codes.add(code)
        self.diagnostics.append(DiagnosticItem("warn", code, message, source))

    def can_consume_entry(self, source: str = "") -> bool:
        self.check()
        if self.entries_seen >= self.limits.max_entries:
            self.mark_limit(
                "DISCOVERY_ENTRY_LIMIT",
                f"Discovery reached entry budget ({self.limits.max_entries}); scan truncated",
                source,
            )
            return False
        return True

    def consume_entry(self, source: str = "") -> bool:
        if not self.can_consume_entry(source):
            return False
        self.entries_seen += 1
        return True

    def next_scandir_entry(self, it: Any, source: str = "") -> os.DirEntry[str] | None:
        if not self.can_consume_entry(source):
            return None
        entry = next(it, None)
        if entry is None:
            return None
        self.entries_seen += 1
        return entry


def _safe_dir_exists(root: Path, rel_path: str) -> bool:
    try:
        target = resolve_workspace_path(root, rel_path, allow_missing=False)
        return target.is_dir() and not is_reparse_or_link(target)
    except (OSError, PathSecurityError, FileNotFoundError):
        return False


def _read_manifest_bytes(
    root: Path,
    rel_path: str,
    *,
    budget: _DiscoveryBudget,
) -> tuple[bytes, str] | None:
    budget.check()
    try:
        return read_regular_file_bounded(
            root,
            rel_path,
            max_file_bytes=budget.limits.max_manifest_bytes,
            bytes_used=budget.bytes_used,
            max_total_bytes=budget.limits.max_total_bytes,
            check_cancel=budget.check,
        )
    except (FileNotFoundError, OSError, PathSecurityError):
        return None
    except ManifestLimitError as exc:
        msg = str(exc)
        if "Total discovery read limit" in msg:
            budget.mark_limit("DISCOVERY_BYTE_LIMIT", msg, rel_path)
        raise _ManifestTooLargeError(msg) from exc


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
    budget: _DiscoveryBudget,
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> tuple[set[str], bool, dict[str, Any]]:
    deps: set[str] = set()
    doc: dict[str, Any] = {}
    has_pytest_cfg = False
    try:
        loaded = _read_manifest_bytes(root, "pyproject.toml", budget=budget)
        if loaded is None:
            return deps, False, doc
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
    return deps, has_pytest_cfg, doc


def _read_requirements_deps(
    root: Path,
    budget: _DiscoveryBudget,
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> set[str]:
    deps: set[str] = set()
    for req_name in ("requirements.txt", "requirements-dev.txt"):
        if not is_safe_regular_file(root, req_name):
            continue
        try:
            loaded = _read_manifest_bytes(root, req_name, budget=budget)
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
        entry = (
            "main:app"
            if is_safe_regular_file(root, "main.py")
            else ("app:app" if is_safe_regular_file(root, "app.py") else "main:app")
        )
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
        entry = "app:app" if is_safe_regular_file(root, "app.py") else "main:app"
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
    if _safe_dir_exists(root, "tests"):
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
    budget: _DiscoveryBudget,
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> tuple[bool, set[str], list[CommandProposal], list[ServerProposal], str, dict[str, Any]]:
    py_venv = _detect_safe_python_venv(root)
    py_exe = str(Path(py_venv) / ("Scripts/python.exe" if os.name == "nt" else "bin/python")) if py_venv else ""
    py_cmd = f'"{py_exe}"' if py_exe else "python"

    has_pyproject = is_safe_regular_file(root, "pyproject.toml")
    py_markers = ("pyproject.toml", "requirements.txt", "requirements-dev.txt", "Pipfile", "main.py", "app.py")
    detected = bool(py_venv) or any(is_safe_regular_file(root, name) for name in py_markers)

    deps: set[str] = set()
    py_doc: dict[str, Any] = {}
    has_pytest_cfg = is_safe_regular_file(root, "pytest.ini")
    if has_pyproject:
        p_deps, p_pytest, py_doc = _read_pyproject_metadata(root, budget, digests, sources, diagnostics)
        deps.update(p_deps)
        has_pytest_cfg = has_pytest_cfg or p_pytest
    deps.update(_read_requirements_deps(root, budget, digests, sources, diagnostics))

    if not detected and not deps:
        return False, set(), [], [], py_venv, py_doc

    cmds = _build_python_commands(root, py_cmd, deps, has_pytest_cfg)
    return True, deps, cmds, _build_python_servers(root, deps, py_exe), py_venv, py_doc


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
        if is_safe_regular_file(root, lock_file):
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
        entry = next((cand for cand in ("server.js", "index.js", "app.js") if is_safe_regular_file(root, cand)), "")
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
    budget: _DiscoveryBudget,
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> dict[str, Any] | None:
    try:
        loaded = _read_manifest_bytes(root, "package.json", budget=budget)
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
    budget: _DiscoveryBudget,
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> tuple[bool, str, list[str], list[CommandProposal], list[ServerProposal], str, dict[str, Any] | None]:
    node_path = _trusted_system_which("node.exe" if os.name == "nt" else "node", project_root=root)
    if not is_safe_regular_file(root, "package.json"):
        return False, "", [], [], [], node_path, None
    pkg = _read_package_json_dict(root, budget, digests, sources, diagnostics)
    if pkg is None:
        return True, "javascript", ["javascript"], [], [], node_path, None

    pm = _resolve_package_manager(root, pkg, sources)
    deps_all = _collect_deps_map(pkg)
    has_ts = is_safe_regular_file(root, "tsconfig.json") or ("typescript" in deps_all)
    language = "typescript" if has_ts else "javascript"
    stacks: list[str] = [language]
    has_next = ("next" in deps_all) or any(is_safe_regular_file(root, f) for f in _NEXT_CONFIG_FILES)
    has_vite = ("vite" in deps_all) or any(is_safe_regular_file(root, f) for f in _VITE_CONFIG_FILES)
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
    return True, language, stacks, cmds, servers, node_path, pkg


def _analyze_compose_project(
    root: Path,
    *,
    budget: _DiscoveryBudget,
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> tuple[bool, list[ServerProposal]]:
    compose_file = next((fname for fname in _COMPOSE_FILENAMES if is_safe_regular_file(root, fname)), "")
    if not compose_file:
        return False, []
    try:
        loaded = _read_manifest_bytes(root, compose_file, budget=budget)
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
            max_bytes=budget.limits.max_manifest_bytes,
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


def _globs_from_package_json_doc(pkg: dict[str, Any] | None) -> list[str]:
    if not isinstance(pkg, dict):
        return []
    ws = pkg.get("workspaces")
    if isinstance(ws, list):
        return [str(x) for x in ws]
    if isinstance(ws, dict) and isinstance(ws.get("packages"), list):
        return [str(x) for x in ws["packages"]]
    return []


def _globs_from_pnpm_yaml(
    root: Path,
    budget: _DiscoveryBudget,
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> list[str]:
    if not is_safe_regular_file(root, "pnpm-workspace.yaml"):
        return []
    try:
        loaded = _read_manifest_bytes(root, "pnpm-workspace.yaml", budget=budget)
        if loaded is None:
            return []
        digests["pnpm-workspace.yaml"] = loaded[1]
        sources.append("pnpm-workspace.yaml")
        ym = parse_safe_yaml_mapping(loaded[0].decode("utf-8"), max_bytes=budget.limits.max_manifest_bytes)
        pkgs = ym.get("packages")
        if isinstance(pkgs, list):
            return [str(x) for x in pkgs]
    except _ManifestTooLargeError as exc:
        diagnostics.append(DiagnosticItem("warn", "MANIFEST_TOO_LARGE", str(exc), "pnpm-workspace.yaml"))
    except Exception as exc:  # noqa: BLE001
        diagnostics.append(DiagnosticItem("warn", "MANIFEST_PARSE_ERROR", redact_discovery_text(str(exc)), "pnpm-workspace.yaml"))
    return []


def _globs_from_pyproject_doc(py_doc: dict[str, Any]) -> list[str]:
    uv_ws = py_doc.get("tool", {}).get("uv", {}).get("workspace", {})
    if isinstance(uv_ws, dict) and isinstance(uv_ws.get("members"), list):
        return [str(x) for x in uv_ws["members"]]
    return []


def _extract_workspace_globs(
    root: Path,
    *,
    pkg_doc: dict[str, Any] | None,
    py_doc: dict[str, Any],
    budget: _DiscoveryBudget,
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> list[str]:
    globs = [
        *_globs_from_package_json_doc(pkg_doc),
        *_globs_from_pnpm_yaml(root, budget, digests, sources, diagnostics),
        *_globs_from_pyproject_doc(py_doc),
    ]
    return list(dict.fromkeys(globs))[:24]


def _is_safe_workspace_glob(pattern: str) -> str | None:
    clean = pattern.strip().replace("\\", "/")
    if not clean or clean.startswith("!") or clean.startswith("/") or ":" in clean or "**" in clean:
        return None
    parts = PurePosixPath(clean).parts
    if any(
        part in ("..", ".")
        or part.casefold() in EXCLUDED_DISCOVERY_DIRS
        or is_sensitive_segment(part)
        or _is_reserved_win_name(part)
        for part in parts
    ):
        return None
    return clean.rstrip("/")


def _is_safe_scandir_subdir(entry: os.DirEntry[str]) -> bool:
    name = entry.name
    if name.casefold() in EXCLUDED_DISCOVERY_DIRS or is_sensitive_segment(name) or _is_reserved_win_name(name):
        return False
    try:
        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
            return False
        return not is_reparse_or_link(Path(entry.path))
    except OSError:
        return False


def _step_literal_segment(
    parent: Path,
    segment: str,
    budget: _DiscoveryBudget,
) -> Path | None:
    if not budget.consume_entry("monorepo"):
        return None
    if segment.casefold() in EXCLUDED_DISCOVERY_DIRS or is_sensitive_segment(segment) or _is_reserved_win_name(segment):
        return None
    cand = parent / segment
    try:
        st = os.lstat(cand)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or is_reparse_or_link(cand):
            return None
        return cand
    except OSError:
        return None


def _step_wildcard_segment(
    parent: Path,
    segment: str,
    budget: _DiscoveryBudget,
    limit: int,
) -> list[Path]:
    matched: list[Path] = []
    try:
        with os.scandir(parent) as it:
            while len(matched) < limit:
                entry = budget.next_scandir_entry(it, "monorepo")
                if entry is None:
                    break
                if not _is_safe_scandir_subdir(entry):
                    continue
                matches_fn = fnmatch.fnmatch if os.name == "nt" else fnmatch.fnmatchcase
                if matches_fn(entry.name, segment):
                    matched.append(Path(entry.path))
    except OSError:
        return matched
    return matched


def _try_add_monorepo_match(
    root: Path,
    match: Path,
    seen_roots: set[str],
    *,
    budget: _DiscoveryBudget,
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
    if rel in seen_roots or any(seg.casefold() in EXCLUDED_DISCOVERY_DIRS or is_sensitive_segment(seg) for seg in rel_parts):
        return None
    seen_roots.add(rel)
    sub_res = _analyze_directory_with_budget(
        canon,
        budget=budget,
        allow_parent_git_lookup=False,
        include_subprojects=False,
        collect_all_significant=False,
    )
    return SubprojectCandidate(
        relative_path=rel,
        root_path=str(canon),
        name=sub_res.name,
        language=sub_res.language,
        confidence=sub_res.confidence,
        source=", ".join(sub_res.sources) or "monorepo",
    )


def _advance_glob_dirs(
    cur_dirs: list[Path],
    segment: str,
    budget: _DiscoveryBudget,
) -> list[Path]:
    has_wild = any(ch in segment for ch in ("*", "?", "["))
    next_dirs: list[Path] = []
    for parent in cur_dirs:
        budget.check()
        if budget.truncated or len(next_dirs) >= 24:
            break
        if has_wild:
            next_dirs.extend(_step_wildcard_segment(parent, segment, budget, 24 - len(next_dirs)))
            continue
        lit = _step_literal_segment(parent, segment, budget)
        if lit is not None:
            next_dirs.append(lit)
    return next_dirs


def _expand_safe_glob_bounded(
    root: Path,
    safe_pat: str,
    seen_roots: set[str],
    candidates: list[SubprojectCandidate],
    *,
    budget: _DiscoveryBudget,
    diagnostics: list[DiagnosticItem],
) -> bool:
    parts = PurePosixPath(safe_pat).parts
    if not parts or len(parts) > budget.limits.max_depth:
        diagnostics.append(
            DiagnosticItem("warn", "WORKSPACE_GLOB_REJECTED", f"Monorepo glob exceeds max depth ({budget.limits.max_depth}): {safe_pat!r}")
        )
        return False

    cur_dirs: list[Path] = [root]
    for seg in parts:
        cur_dirs = _advance_glob_dirs(cur_dirs, seg, budget)
        if not cur_dirs or budget.truncated:
            break

    for match in cur_dirs:
        budget.check()
        if len(candidates) >= 24:
            return True
        cand = _try_add_monorepo_match(root, match, seen_roots, budget=budget)
        if cand is not None:
            candidates.append(cand)
        if budget.truncated or len(candidates) >= 24:
            return True
    return False


def _discover_monorepo_subprojects(
    root: Path,
    *,
    pkg_doc: dict[str, Any] | None,
    py_doc: dict[str, Any],
    budget: _DiscoveryBudget,
    digests: dict[str, str],
    sources: list[str],
    diagnostics: list[DiagnosticItem],
) -> tuple[SubprojectCandidate, ...]:
    raw_globs = _extract_workspace_globs(
        root,
        pkg_doc=pkg_doc,
        py_doc=py_doc,
        budget=budget,
        digests=digests,
        sources=sources,
        diagnostics=diagnostics,
    )
    if not raw_globs:
        return ()
    seen_roots: set[str] = set()
    candidates: list[SubprojectCandidate] = []
    for raw_pat in raw_globs:
        budget.check()
        if budget.truncated or len(candidates) >= 24:
            break
        if raw_pat.strip().startswith("!"):
            continue
        safe_pat = _is_safe_workspace_glob(raw_pat)
        if safe_pat is None:
            diagnostics.append(DiagnosticItem("warn", "WORKSPACE_GLOB_REJECTED", f"Unsafe monorepo glob rejected: {raw_pat!r}"))
            continue
        if _expand_safe_glob_bounded(
            root, safe_pat, seen_roots, candidates, budget=budget, diagnostics=diagnostics
        ):
            break
    candidates.sort(key=lambda c: c.relative_path.casefold())
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


def _collect_remaining_significant_digests(
    root: Path,
    digests: dict[str, str],
    budget: _DiscoveryBudget,
    diagnostics: list[DiagnosticItem],
) -> dict[str, str]:
    merged, issues = collect_significant_manifest_digests(
        root,
        existing_digests=digests,
        max_file_bytes=budget.limits.max_manifest_bytes,
        bytes_used=budget.bytes_used,
        max_total_bytes=budget.limits.max_total_bytes,
        check_cancel=budget.check,
    )
    for rel, reason in issues:
        if "Total discovery read limit" in reason:
            budget.mark_limit("DISCOVERY_BYTE_LIMIT", reason, rel)
        else:
            diagnostics.append(DiagnosticItem("warn", "MANIFEST_HASH_SKIPPED", redact_discovery_text(reason), rel))
    return merged


def _analyze_directory_with_budget(
    root: Path,
    *,
    budget: _DiscoveryBudget,
    allow_parent_git_lookup: bool,
    include_subprojects: bool,
    collect_all_significant: bool,
) -> WorkspaceDiscoveryResult:
    budget.check()
    root_ident = compute_root_identity(root)

    digests: dict[str, str] = {}
    sources: list[str] = []
    diagnostics: list[DiagnosticItem] = []

    git_root, git_verified, git_diags = _inspect_git_boundary(
        root, allow_parent_git_lookup=allow_parent_git_lookup
    )
    diagnostics.extend(git_diags)
    if git_verified:
        sources.append(".git")

    budget.check()
    py_ok, _py_deps, py_cmds, py_srvs, py_venv, py_doc = _analyze_python_project(
        root, budget=budget, digests=digests, sources=sources, diagnostics=diagnostics
    )
    budget.check()
    node_ok, node_lang, node_stacks, node_cmds, node_srvs, node_path, pkg_doc = _analyze_node_project(
        root, budget=budget, digests=digests, sources=sources, diagnostics=diagnostics
    )
    budget.check()
    compose_ok, compose_srvs = _analyze_compose_project(
        root, budget=budget, digests=digests, sources=sources, diagnostics=diagnostics
    )

    subprojects: tuple[SubprojectCandidate, ...] = ()
    if include_subprojects:
        subprojects = _discover_monorepo_subprojects(
            root,
            pkg_doc=pkg_doc,
            py_doc=py_doc,
            budget=budget,
            digests=digests,
            sources=sources,
            diagnostics=diagnostics,
        )

    stacks: list[str] = []
    if node_ok:
        stacks.extend(node_stacks)
    if py_ok:
        stacks.append("python")
    if compose_ok:
        stacks.append("docker_compose")
    for fname, stack_name in (("Cargo.toml", "rust"), ("go.mod", "go")):
        if is_safe_regular_file(root, fname):
            stacks.append(stack_name)
            sources.append(fname)

    if collect_all_significant and not budget.truncated:
        digests = _collect_remaining_significant_digests(root, digests, budget, diagnostics)
    diagnostics.extend(budget.diagnostics)

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
        truncated=budget.truncated,
    )


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
    budget = _DiscoveryBudget(limits=cfg, start_t=time.monotonic(), cancel_event=cancel_event)
    budget.check()
    root = _require_safe_root(root_path)
    return _analyze_directory_with_budget(
        root,
        budget=budget,
        allow_parent_git_lookup=allow_parent_git_lookup,
        include_subprojects=include_subprojects,
        collect_all_significant=True,
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
        if is_safe_regular_file(directory, fname):
            if fname == "package.json" and is_safe_regular_file(directory, "tsconfig.json"):
                return True, "typescript", "package.json + tsconfig.json"
            return True, lang, src
    return False, "generic", ""


def _enqueue_scandir_child(
    root: Path,
    entry: os.DirEntry[str],
    depth: int,
    depth_cap: int,
    queue: deque[tuple[Path, int]],
    found: list[SubprojectCandidate],
) -> None:
    if not _is_safe_scandir_subdir(entry):
        return
    child = Path(entry.path)
    has_marker, lang, src = _has_project_marker(child)
    if has_marker:
        found.append(
            SubprojectCandidate(
                relative_path=child.relative_to(root).as_posix(),
                root_path=str(child),
                name=entry.name,
                language=lang,
                confidence="medium",
                source=src,
            )
        )
    if depth < depth_cap:
        queue.append((child, depth + 1))


def _scan_children_bounded(
    root: Path,
    depth_cap: int,
    budget: _DiscoveryBudget,
    found: list[SubprojectCandidate],
) -> None:
    queue: deque[tuple[Path, int]] = deque([(root, 1)])
    while queue and not budget.truncated and len(found) < 50:
        cur, depth = queue.popleft()
        try:
            with os.scandir(cur) as it:
                while len(found) < 50:
                    entry = budget.next_scandir_entry(it, "parent_scan")
                    if entry is None:
                        break
                    _enqueue_scandir_child(root, entry, depth, depth_cap, queue, found)
        except OSError:
            continue


def discover_projects_in_directory(
    parent_path: str | Path,
    *,
    max_depth: int = 2,
    limits: DiscoveryLimits | None = None,
    cancel_event: threading.Event | None = None,
    diagnostics_out: list[DiagnosticItem] | None = None,
) -> list[SubprojectCandidate]:
    """Bounded read-only lazy BFS scan of subdirectories under a user-selected parent folder."""
    cfg = limits or DiscoveryLimits()
    budget = _DiscoveryBudget(limits=cfg, start_t=time.monotonic(), cancel_event=cancel_event)
    budget.check()
    root = _require_safe_root(parent_path)
    depth_cap = max(1, min(int(max_depth), cfg.max_depth))
    found: list[SubprojectCandidate] = []
    _scan_children_bounded(root, depth_cap, budget, found)
    found.sort(key=lambda c: c.relative_path.casefold())
    if diagnostics_out is not None and budget.diagnostics:
        diagnostics_out.extend(budget.diagnostics)
    return found


def compute_current_manifest_digests(root: Path, paths: Iterable[str]) -> dict[str, str]:
    """Recompute SHA-256 digests for approved manifest relative paths inside `root`."""
    canon_root = canonical_workspace_root(root)
    budget = [0]
    out: dict[str, str] = {}
    for rel in paths:
        try:
            out[rel] = hash_regular_file_bounded(canon_root, rel, bytes_used=budget)
        except (FileNotFoundError, OSError, PathSecurityError, ManifestLimitError):
            continue
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
