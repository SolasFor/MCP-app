"""Safe built-in server templates with strict parameter validation and loopback defaults."""
from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

from backend.servers.models import (
    LOOPBACK_HOSTS,
    ReadinessConfig,
    RestartConfig,
    ServerProfile,
    validate_server_name,
)

_DANGEROUS_CHARS_RE = re.compile(r"[;|&`$><\r\n\x00]")
_ASGI_ENTRYPOINT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")
_FLASK_ENTRYPOINT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_./:-]{0,127}$")
_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_DISALLOWED_EXECUTABLES = frozenset({
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "sh", "bash", "zsh", "pip", "pip.exe", "pip3", "pip3.exe",
    "npm", "npm.cmd", "npx", "npx.cmd", "yarn", "yarn.cmd", "pnpm", "pnpm.cmd",
})


def _reject_dangerous(value: str, label: str) -> str:
    clean = (value or "").strip()
    if not clean or _DANGEROUS_CHARS_RE.search(clean):
        raise ValueError(f"Unsafe or empty value for {label}")
    return clean


def _validate_relative_file(cwd: Path, rel: str, label: str) -> str:
    clean = _reject_dangerous(rel, label)
    p = Path(clean)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError(f"{label} must be a relative path inside cwd without '..'")
    resolved_cwd = cwd.resolve()
    target = (resolved_cwd / p).resolve()
    try:
        target.relative_to(resolved_cwd)
    except ValueError as exc:
        raise ValueError(f"{label} escapes working directory") from exc
    return clean


def _resolve_executable(explicit: str, fallbacks: tuple[str, ...]) -> str:
    candidate = (explicit or "").strip()
    if not candidate:
        for fb in fallbacks:
            if Path(fb).is_absolute():
                if Path(fb).is_file():
                    candidate = fb
                    break
            else:
                found = shutil.which(fb)
                if found:
                    candidate = found
                    break
    if not candidate:
        raise ValueError(f"Required runtime executable not found ({', '.join(fallbacks)})")
    exe_path = Path(candidate)
    if exe_path.name.lower() in _DISALLOWED_EXECUTABLES:
        raise ValueError(f"Template refuses shell or package-manager executable: {exe_path.name}")
    if not exe_path.is_absolute():
        resolved = shutil.which(candidate)
        if resolved:
            exe_path = Path(resolved)
    if not exe_path.is_absolute():
        raise ValueError(f"Executable path must be absolute: {candidate}")
    if os.name == "nt" and exe_path.suffix.lower() != ".exe":
        raise ValueError("Windows managed server templates require a direct .exe binary")
    return str(exe_path)


def _validate_host(host: str, *, expose_externally: bool) -> str:
    clean = _reject_dangerous(host or "127.0.0.1", "host")
    if clean.lower() not in LOOPBACK_HOSTS and not expose_externally:
        raise ValueError("Refusing non-loopback host bind unless expose_externally=True")
    return clean


def _validate_port(port: int | None, default_port: int | None) -> int | None:
    chosen = default_port if port is None else int(port)
    if chosen is not None and not (1 <= chosen <= 65535):
        raise ValueError("Port must be between 1 and 65535")
    return chosen


def list_templates() -> list[dict[str, Any]]:
    """Return metadata for built-in server templates."""
    return [
        {
            "template": "python_fastapi",
            "title": "Python FastAPI (uvicorn)",
            "default_port": 8001,
            "default_readiness": "http",
            "default_health_path": "/health",
            "default_entrypoint": "main:app",
        },
        {
            "template": "python_flask",
            "title": "Python Flask",
            "default_port": 5000,
            "default_readiness": "tcp",
            "default_health_path": "/",
            "default_entrypoint": "app:app",
        },
        {
            "template": "node_express",
            "title": "Node.js / Express",
            "default_port": 3000,
            "default_readiness": "tcp",
            "default_health_path": "/health",
            "default_entrypoint": "server.js",
        },
        {
            "template": "vite_next",
            "title": "Vite / Next.js Dev Server",
            "default_port": 5173,
            "default_readiness": "tcp",
            "default_health_path": "/",
            "default_entrypoint": "vite",
        },
        {
            "template": "docker_compose",
            "title": "Docker Compose Stack",
            "default_port": None,
            "default_readiness": "none",
            "default_health_path": "/",
            "default_entrypoint": "docker-compose.yml",
        },
        {
            "template": "static_http",
            "title": "Python Static HTTP Server",
            "default_port": 8080,
            "default_readiness": "http",
            "default_health_path": "/",
            "default_entrypoint": ".",
        },
        {
            "template": "custom",
            "title": "Custom Executable",
            "default_port": None,
            "default_readiness": "none",
            "default_health_path": "/health",
            "default_entrypoint": "",
        },
    ]


def build_profile_from_template(
    *,
    name: str,
    template: str,
    cwd: str,
    host: str = "127.0.0.1",
    port: int | None = None,
    expose_externally: bool = False,
    executable: str = "",
    entrypoint: str = "",
    extra_args: tuple[str, ...] = (),
    lifecycle: str = "controlled",
    readiness_kind: str | None = None,
    health_path: str | None = None,
    restart_policy: str = "never",
    autostart: bool = False,
    min_profile: str = "full",
    allowed_clients: tuple[str, ...] = (),
    depends_on: tuple[str, ...] = (),
    display_name: str = "",
    description: str = "",
) -> ServerProfile:
    """Validate template inputs and materialize an explicit, non-shell ServerProfile."""
    clean_name = validate_server_name(name)
    cwd_path = Path(cwd)
    if not cwd_path.is_absolute():
        raise ValueError("Working directory (cwd) must be an absolute path")
    clean_host = _validate_host(host, expose_externally=expose_externally)
    env: dict[str, str] = {}
    argv: list[str] = []
    chosen_port: int | None = port
    default_readiness = "none"
    default_health = "/health"
    template_params: dict[str, Any] = {}

    if extra_args:
        for arg in extra_args:
            if not isinstance(arg, str) or not arg or _DANGEROUS_CHARS_RE.search(arg):
                raise ValueError("Unsafe extra argument in template")

    if template == "python_fastapi":
        chosen_port = _validate_port(port, 8001)
        assert chosen_port is not None
        exe = _resolve_executable(executable, (sys.executable, "python"))
        target = _reject_dangerous(entrypoint or "main:app", "entrypoint")
        if not _ASGI_ENTRYPOINT_RE.fullmatch(target):
            raise ValueError("FastAPI entrypoint must have form module:app")
        argv = [exe, "-m", "uvicorn", target, "--host", clean_host, "--port", str(chosen_port)]
        default_readiness = "http"
        default_health = "/health"
        template_params = {"entrypoint": target}

    elif template == "python_flask":
        chosen_port = _validate_port(port, 5000)
        assert chosen_port is not None
        exe = _resolve_executable(executable, (sys.executable, "python"))
        target = _reject_dangerous(entrypoint or "app:app", "entrypoint")
        if not _FLASK_ENTRYPOINT_RE.fullmatch(target) or ".." in target:
            raise ValueError("Invalid Flask app entrypoint")
        argv = [
            exe, "-m", "flask", "--app", target, "run",
            "--host", clean_host, "--port", str(chosen_port),
            "--no-debugger", "--no-reload",
        ]
        default_readiness = "tcp"
        default_health = "/"
        template_params = {"entrypoint": target}

    elif template == "node_express":
        chosen_port = _validate_port(port, 3000)
        assert chosen_port is not None
        exe = _resolve_executable(executable, ("node.exe" if os.name == "nt" else "node",))
        script_rel = _validate_relative_file(cwd_path, entrypoint or "server.js", "entrypoint")
        argv = [exe, script_rel]
        env.update({"HOST": clean_host, "PORT": str(chosen_port)})
        default_readiness = "tcp"
        default_health = "/health"
        template_params = {"entrypoint": script_rel}

    elif template == "vite_next":
        framework = (entrypoint or "vite").strip().lower()
        if framework not in ("vite", "next"):
            raise ValueError("vite_next entrypoint/framework must be 'vite' or 'next'")
        chosen_port = _validate_port(port, 5173 if framework == "vite" else 3000)
        assert chosen_port is not None
        exe = _resolve_executable(executable, ("node.exe" if os.name == "nt" else "node",))
        if framework == "vite":
            bin_rel = _validate_relative_file(cwd_path, "node_modules/vite/bin/vite.js", "vite binary")
            argv = [exe, bin_rel, "--host", clean_host, "--port", str(chosen_port)]
        else:
            bin_rel = _validate_relative_file(cwd_path, "node_modules/next/dist/bin/next", "next binary")
            argv = [exe, bin_rel, "dev", "-H", clean_host, "-p", str(chosen_port)]
        default_readiness = "tcp"
        default_health = "/"
        template_params = {"framework": framework}

    elif template == "docker_compose":
        chosen_port = _validate_port(port, None)
        exe = _resolve_executable(executable, ("docker.exe" if os.name == "nt" else "docker",))
        compose_raw = entrypoint or "docker-compose.yml"
        if ":" in compose_raw and not Path(compose_raw).is_absolute():
            compose_part, service_part = compose_raw.split(":", 1)
            compose_file = _validate_relative_file(cwd_path, compose_part, "compose file")
            service_clean = service_part.strip()
            if not _SERVICE_NAME_RE.fullmatch(service_clean):
                raise ValueError("Invalid docker compose service name")
            argv = [exe, "compose", "-f", compose_file, "up", "--no-build", service_clean]
            template_params = {"compose_file": compose_file, "service": service_clean}
        else:
            compose_file = _validate_relative_file(cwd_path, compose_raw, "compose file")
            argv = [exe, "compose", "-f", compose_file, "up", "--no-build"]
            template_params = {"compose_file": compose_file}
        default_readiness = "tcp" if chosen_port else "none"
        default_health = "/"

    elif template == "static_http":
        chosen_port = _validate_port(port, 8080)
        assert chosen_port is not None
        exe = _resolve_executable(executable, (sys.executable, "python"))
        serve_dir = _validate_relative_file(cwd_path, entrypoint or ".", "static directory")
        argv = [
            exe, "-m", "http.server", str(chosen_port),
            "--bind", clean_host, "--directory", serve_dir,
        ]
        default_readiness = "http"
        default_health = "/"
        template_params = {"directory": serve_dir}

    elif template == "custom":
        chosen_port = _validate_port(port, None)
        exe = _resolve_executable(executable, ())
        argv = [exe, *extra_args]
        default_readiness = "tcp" if chosen_port else "none"
        default_health = "/health"
    else:
        raise ValueError(f"Unsupported server template: {template!r}")

    if template != "custom" and extra_args:
        argv.extend(extra_args)

    eff_readiness_kind = (readiness_kind or default_readiness).strip().lower()
    if eff_readiness_kind != "none" and chosen_port is None:
        raise ValueError("TCP/HTTP readiness check requires a configured port")

    probe_host = "127.0.0.1" if clean_host in ("0.0.0.0", "::") else clean_host
    readiness = ReadinessConfig(
        kind=eff_readiness_kind,
        host=probe_host,
        port=chosen_port,
        http_path=(health_path or default_health),
    )
    restart = RestartConfig(policy=restart_policy)

    profile = ServerProfile(
        name=clean_name,
        display_name=display_name or clean_name,
        template=template,
        argv=tuple(argv),
        cwd=str(cwd_path),
        env=env,
        lifecycle=lifecycle,
        host=clean_host,
        port=chosen_port,
        expose_externally=expose_externally,
        readiness=readiness,
        depends_on=tuple(depends_on),
        restart=restart,
        autostart=autostart,
        min_profile=min_profile,
        allowed_clients=tuple(allowed_clients),
        template_params=template_params,
        description=description,
    )
    profile.validate()
    return profile
