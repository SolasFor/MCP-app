"""Safe Git operations with untrusted-hook/filter suppression and zero console windows."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.core.redaction import SecretRedactor, sanitize_child_env
from backend.workspaces.models import MAX_READ_BYTES, WorkspaceProfile
from backend.workspaces.path_security import (
    PathSecurityError,
    canonical_workspace_root,
    resolve_workspace_path,
)

_BRANCH_NAME_RE = re.compile(r"^[A-Za-z0-9._/-]{1,128}$")


def _safe_branch_name(name: str) -> str:
    clean = (name or "").strip()
    if (
        not _BRANCH_NAME_RE.fullmatch(clean)
        or clean.startswith("-")
        or ".." in clean
        or clean.endswith(".lock")
        or clean.startswith("/")
        or clean.endswith("/")
    ):
        raise ValueError(f"Invalid branch name: {name!r}")
    return clean


def _git_executable() -> str:
    exe = shutil.which("git")
    if not exe:
        raise RuntimeError("git executable was not found on PATH")
    return exe


def _run_git(
    repo_root: Path,
    args: list[str],
    *,
    trust_hooks: bool,
    nohooks_dir: Path,
    redactor: SecretRedactor | None = None,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    git_exe = _git_executable()
    cmd = [git_exe]
    if not trust_hooks:
        nohooks_dir.mkdir(parents=True, exist_ok=True)
        cmd.extend([
            "-c", f"core.hooksPath={nohooks_dir}",
            "-c", "core.fsmonitor=false",
            "-c", "core.sshCommand=false",
            "-c", "diff.external=",
            "-c", "credential.helper=",
            "-c", "protocol.ext.allow=never",
            "-c", "filter.lfs.smudge=",
            "-c", "filter.lfs.clean=",
            "-c", "filter.lfs.process=",
        ])
    cmd.extend(args)

    env = sanitize_child_env(extra_env={
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    kwargs: dict[str, Any] = {
        "cwd": str(repo_root),
        "env": env,
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": timeout,
        "stdin": subprocess.DEVNULL,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

    res = subprocess.run(cmd, **kwargs)
    if res.returncode != 0:
        err = res.stderr.strip() or res.stdout.strip() or f"git exited with code {res.returncode}"
        if redactor is not None:
            err = redactor.redact_text(err)
        raise RuntimeError(err)
    return res


def _repo_root_for(profile: WorkspaceProfile) -> Path:
    root = canonical_workspace_root(profile.root_path)
    if not (root / ".git").exists():
        # Verify whether git_root is explicitly configured and equals root or ancestor
        if profile.git_root:
            candidate = canonical_workspace_root(profile.git_root)
            if root == candidate or root.is_relative_to(candidate):
                return candidate
        raise ValueError("Workspace is not inside a Git repository")
    return root


def _bound_text(text: str, redactor: SecretRedactor | None) -> str:
    if redactor is not None:
        text = redactor.redact_text(text)
    if len(text) > MAX_READ_BYTES:
        return text[:MAX_READ_BYTES] + "\n... [OUTPUT TRUNCATED]"
    return text


def git_status(
    profile: WorkspaceProfile,
    *,
    nohooks_dir: Path,
    redactor: SecretRedactor | None = None,
) -> dict[str, Any]:
    repo = _repo_root_for(profile)
    res = _run_git(
        repo,
        ["status", "--porcelain=v1", "-b"],
        trust_hooks=profile.trust_git_hooks,
        nohooks_dir=nohooks_dir,
        redactor=redactor,
    )
    lines = res.stdout.splitlines()
    branch_line = lines[0] if lines else ""
    changes: list[dict[str, str]] = []
    for line in lines[1:]:
        if len(line) >= 4:
            changes.append({"status": line[:2].strip() or "??", "path": line[3:].strip()})
    return {
        "workspace_id": profile.workspace_id,
        "branch": branch_line.removeprefix("## ").strip(),
        "clean": len(changes) == 0,
        "changes": changes[:500],
        "trust_git_hooks": profile.trust_git_hooks,
    }


def git_diff(
    profile: WorkspaceProfile,
    *,
    nohooks_dir: Path,
    staged: bool = False,
    relative_path: str = "",
    redactor: SecretRedactor | None = None,
) -> dict[str, Any]:
    repo = _repo_root_for(profile)
    root = canonical_workspace_root(profile.root_path)
    args = ["diff", "--no-ext-diff"]
    if staged:
        args.append("--cached")
    if relative_path:
        target = resolve_workspace_path(root, relative_path, allow_missing=True, exclude_patterns=profile.exclude_patterns)
        args.extend(["--", target.relative_to(repo).as_posix()])
    res = _run_git(repo, args, trust_hooks=profile.trust_git_hooks, nohooks_dir=nohooks_dir, redactor=redactor)
    return {
        "workspace_id": profile.workspace_id,
        "staged": staged,
        "diff": _bound_text(res.stdout, redactor),
    }


def git_log(
    profile: WorkspaceProfile,
    *,
    nohooks_dir: Path,
    limit: int = 20,
    redactor: SecretRedactor | None = None,
) -> dict[str, Any]:
    repo = _repo_root_for(profile)
    n = max(1, min(int(limit), 100))
    res = _run_git(
        repo,
        ["log", f"-n{n}", "--date=iso-strict", "--pretty=format:%H%x1f%an%x1f%ad%x1f%s"],
        trust_hooks=profile.trust_git_hooks,
        nohooks_dir=nohooks_dir,
        redactor=redactor,
    )
    commits: list[dict[str, str]] = []
    for row in res.stdout.splitlines():
        parts = row.split("\x1f", 3)
        if len(parts) == 4:
            commits.append({
                "sha": parts[0],
                "author": parts[1],
                "date": parts[2],
                "subject": redactor.redact_text(parts[3]) if redactor else parts[3],
            })
    return {"workspace_id": profile.workspace_id, "commits": commits}


def git_branches(
    profile: WorkspaceProfile,
    *,
    nohooks_dir: Path,
    redactor: SecretRedactor | None = None,
) -> dict[str, Any]:
    repo = _repo_root_for(profile)
    res = _run_git(
        repo,
        ["branch", "--format=%(HEAD)|%(refname:short)"],
        trust_hooks=profile.trust_git_hooks,
        nohooks_dir=nohooks_dir,
        redactor=redactor,
    )
    current = ""
    branches: list[str] = []
    for line in res.stdout.splitlines():
        if "|" not in line:
            continue
        head, bname = line.split("|", 1)
        bname = bname.strip()
        if bname:
            branches.append(bname)
            if head.strip() == "*":
                current = bname
    return {"workspace_id": profile.workspace_id, "current": current, "branches": branches}


def git_checkout(
    profile: WorkspaceProfile,
    branch: str,
    *,
    create: bool = False,
    nohooks_dir: Path,
    redactor: SecretRedactor | None = None,
) -> dict[str, Any]:
    clean_branch = _safe_branch_name(branch)
    repo = _repo_root_for(profile)
    args = ["checkout", "-b", clean_branch] if create else ["checkout", clean_branch]
    _run_git(repo, args, trust_hooks=profile.trust_git_hooks, nohooks_dir=nohooks_dir, redactor=redactor)
    return {"workspace_id": profile.workspace_id, "branch": clean_branch, "created": bool(create)}


def git_commit(
    profile: WorkspaceProfile,
    message: str,
    *,
    paths: list[str] | tuple[str, ...] = (),
    nohooks_dir: Path,
    redactor: SecretRedactor | None = None,
) -> dict[str, Any]:
    clean_msg = (message or "").strip()
    if not clean_msg or "\x00" in clean_msg:
        raise ValueError("Commit message is required")
    if not paths:
        raise ValueError("Specify explicit relative paths to stage and commit")

    repo = _repo_root_for(profile)
    root = canonical_workspace_root(profile.root_path)
    repo_rels: list[str] = []
    for p in paths:
        target = resolve_workspace_path(
            root, p, allow_missing=True, exclude_patterns=profile.exclude_patterns
        )
        if not target.is_relative_to(repo):
            raise PathSecurityError("Commit path escapes repository root")
        repo_rels.append(target.relative_to(repo).as_posix())

    _run_git(
        repo,
        ["add", "--", *repo_rels],
        trust_hooks=profile.trust_git_hooks,
        nohooks_dir=nohooks_dir,
        redactor=redactor,
    )
    commit_args = ["commit"]
    if not profile.trust_git_hooks:
        commit_args.append("--no-verify")
    commit_args.extend(["-m", clean_msg, "--", *repo_rels])
    _run_git(repo, commit_args, trust_hooks=profile.trust_git_hooks, nohooks_dir=nohooks_dir, redactor=redactor)
    head = _run_git(
        repo,
        ["rev-parse", "--short", "HEAD"],
        trust_hooks=profile.trust_git_hooks,
        nohooks_dir=nohooks_dir,
        redactor=redactor,
    )
    return {
        "workspace_id": profile.workspace_id,
        "sha": head.stdout.strip(),
        "files": repo_rels,
        "hooks_suppressed": not profile.trust_git_hooks,
    }
