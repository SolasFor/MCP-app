"""Auto-detection and safe parsing of local AI client MCP configurations (JSON & TOML)."""
from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.gateway.models import (
    AUTH_BEARER,
    AUTH_HEADERS,
    AUTH_NONE,
    TRANSPORT_SSE,
    TRANSPORT_STDIO,
    TRANSPORT_STREAMABLE_HTTP,
    UpstreamServerProfile,
    normalize_server_id,
)
from backend.gateway.security import detect_untrusted_launcher, looks_like_secret_env_name
from backend.gateway.store import GatewayConfigStore


@dataclass(frozen=True)
class DetectedClientSource:
    client_key: str
    display_name_ru: str
    display_name_en: str
    config_path: Path | None
    exists: bool
    format: str  # json | toml | cloud_only
    note_ru: str = ""
    note_en: str = ""


@dataclass(frozen=True)
class ParsedImportCandidate:
    source_name: str
    profile: UpstreamServerProfile
    secret_env: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None
    secret_headers: dict[str, str] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    duplicate_of: str | None = None


def detect_ai_client_configs(*, cwd: Path | None = None) -> list[DetectedClientSource]:
    """Locate real local configuration files for supported AI clients on this machine."""
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA") or (home / "AppData" / "Roaming"))
    codex_home = Path(os.environ.get("CODEX_HOME") or (home / ".codex"))
    work_dir = cwd or Path.cwd()

    specs: list[tuple[str, str, str, Path | None, str, str, str]] = [
        (
            "claude_desktop",
            "Claude Desktop",
            "Claude Desktop",
            appdata / "Claude" / "claude_desktop_config.json",
            "json",
            "Файл конфигурации Claude Desktop.",
            "Claude Desktop local MCP configuration.",
        ),
        (
            "claude_code_user",
            "Claude Code (~/.claude.json)",
            "Claude Code (~/.claude.json)",
            home / ".claude.json",
            "json",
            "Пользовательская конфигурация Claude Code.",
            "Claude Code user configuration.",
        ),
        (
            "claude_code_project",
            "Claude Code (.mcp.json)",
            "Claude Code (.mcp.json)",
            work_dir / ".mcp.json",
            "json",
            "Проектный файл .mcp.json в текущем рабочем каталоге.",
            "Project-scoped .mcp.json in current working directory.",
        ),
        (
            "cursor",
            "Cursor",
            "Cursor",
            home / ".cursor" / "mcp.json",
            "json",
            "Конфигурация MCP редактора Cursor.",
            "Cursor global MCP configuration.",
        ),
        (
            "vscode_mcp",
            "VS Code (mcp.json)",
            "VS Code (mcp.json)",
            appdata / "Code" / "User" / "mcp.json",
            "json",
            "Отдельный файл MCP-серверов VS Code.",
            "VS Code standalone MCP configuration.",
        ),
        (
            "vscode_settings",
            "VS Code (settings.json)",
            "VS Code (settings.json)",
            appdata / "Code" / "User" / "settings.json",
            "json",
            "Раздел mcp.servers внутри настроек VS Code.",
            "VS Code settings.json (mcp.servers section).",
        ),
        (
            "codex",
            "OpenAI Codex (config.toml)",
            "OpenAI Codex (config.toml)",
            codex_home / "config.toml",
            "toml",
            "TOML-конфигурация OpenAI Codex CLI / App.",
            "OpenAI Codex CLI / App TOML configuration.",
        ),
        (
            "chatgpt_web",
            "ChatGPT Web",
            "ChatGPT Web",
            None,
            "cloud_only",
            "ChatGPT Web хранит коннекторы в облаке и не имеет локального конфиг-файла.",
            "ChatGPT Web stores connectors in the cloud and has no local config file.",
        ),
    ]
    out: list[DetectedClientSource] = []
    for key, ru_name, en_name, path, fmt, ru_note, en_note in specs:
        exists = bool(path is not None and path.is_file())
        out.append(
            DetectedClientSource(
                client_key=key,
                display_name_ru=ru_name,
                display_name_en=en_name,
                config_path=path,
                exists=exists,
                format=fmt,
                note_ru=ru_note,
                note_en=en_note,
            )
        )
    return out


def _extract_servers_mapping(data: dict[str, Any]) -> dict[str, Any]:
    for key in ("mcpServers", "servers", "mcp_servers"):
        candidate = data.get(key)
        if isinstance(candidate, dict):
            return candidate
    mcp_section = data.get("mcp")
    if isinstance(mcp_section, dict) and isinstance(mcp_section.get("servers"), dict):
        return mcp_section["servers"]
    return {}


def _find_duplicate_server_id(
    profile: UpstreamServerProfile,
    existing: list[UpstreamServerProfile],
) -> str | None:
    norm_url = profile.url.strip().rstrip("/").lower()
    cmd_sig = (profile.command.strip().lower(), tuple(profile.args))
    for cur in existing:
        if cur.server_id == profile.server_id:
            return cur.server_id
        if norm_url and cur.url.strip().rstrip("/").lower() == norm_url:
            return cur.server_id
        if (
            profile.transport == TRANSPORT_STDIO
            and cur.transport == TRANSPORT_STDIO
            and profile.command
            and (cur.command.strip().lower(), tuple(cur.args)) == cmd_sig
        ):
            return cur.server_id
    return None


def parse_config_text(
    raw_text: str,
    *,
    filename: str = "",
    source_name: str = "manual",
    store: GatewayConfigStore | None = None,
) -> list[ParsedImportCandidate]:
    """Parse JSON (`mcpServers` / `servers` / single object) or TOML (`mcp_servers`) safely."""
    text = (raw_text or "").strip()
    if not text:
        raise ValueError("Configuration content is empty.")

    is_toml = Path(filename).suffix.lower() == ".toml"
    data: dict[str, Any]
    if is_toml:
        loaded = tomllib.loads(text)
        if not isinstance(loaded, dict):
            raise ValueError("TOML root must be a table.")
        data = loaded
    else:
        try:
            loaded = json.loads(text)
            if not isinstance(loaded, dict):
                raise ValueError("JSON root must be an object.")
            data = loaded
        except ValueError:
            # Fallback to TOML if caller pasted Codex config without .toml extension.
            try:
                loaded_toml = tomllib.loads(text)
            except ValueError as exc:
                raise ValueError("Configuration must be valid JSON or TOML.") from exc
            if not isinstance(loaded_toml, dict):
                raise ValueError("Configuration must be valid JSON or TOML.") from None
            data = loaded_toml

    servers_map = _extract_servers_mapping(data)
    if not servers_map:
        # Also allow pasting a single server entry {"command": ..., "args": ...} or {"url": ...}.
        if "command" in data or "url" in data:
            servers_map = {"imported_server": data}
        else:
            raise ValueError("Expected `mcpServers`, `servers`, or `mcp_servers` section in configuration.")

    existing = store.list_profiles() if store is not None else []
    out: list[ParsedImportCandidate] = []
    for raw_id, entry in servers_map.items():
        if not isinstance(entry, dict):
            continue
        sid = normalize_server_id(str(raw_id))
        warnings: list[str] = []
        secret_env: dict[str, str] = {}
        plain_env: dict[str, str] = {}
        secret_headers: dict[str, str] = {}
        bearer_token: str | None = None

        raw_url = str(entry.get("url") or entry.get("serverUrl") or "").strip()
        raw_type = str(entry.get("transport") or entry.get("type") or "").strip().lower()

        if raw_url:
            transport = TRANSPORT_SSE if raw_type == "sse" else TRANSPORT_STREAMABLE_HTTP
            command = ""
            args: tuple[str, ...] = ()
        else:
            transport = TRANSPORT_STDIO
            command = str(entry.get("command") or "").strip()
            raw_args = entry.get("args") or ()
            if isinstance(raw_args, str):
                args = tuple(raw_args.split())
            else:
                args = tuple(str(x) for x in raw_args)
            if detect_untrusted_launcher(command, args):
                warnings.append(
                    f"Launcher `{command}` may download or run external packages; explicit owner review required."
                )

        raw_env = entry.get("env") or {}
        if isinstance(raw_env, dict):
            for k, v in raw_env.items():
                ks, vs = str(k), str(v)
                if "${input:" in vs:
                    warnings.append(f"Env `{ks}` references VS Code placeholder `{vs}`.")
                if looks_like_secret_env_name(ks):
                    secret_env[ks] = vs
                    warnings.append(f"Secret env `{ks}` will be stored in SecretStore.")
                else:
                    plain_env[ks] = vs

        raw_hdrs = entry.get("headers") or entry.get("http_headers") or {}
        if isinstance(raw_hdrs, dict):
            for hk, hv in raw_hdrs.items():
                hks, hvs = str(hk), str(hv)
                if hks.lower() == "authorization" and hvs.lower().startswith("bearer "):
                    bearer_token = hvs[7:].strip()
                    warnings.append("Authorization Bearer header moved into SecretStore.")
                else:
                    secret_headers[hks] = hvs
                    warnings.append(f"Header `{hks}` moved into SecretStore.")

        auth_mode = AUTH_NONE
        if bearer_token:
            auth_mode = AUTH_BEARER
        elif secret_headers:
            auth_mode = AUTH_HEADERS

        allow_local = (
            raw_url.startswith("http://127.0.0.1")
            or raw_url.startswith("http://localhost")
            or raw_url.startswith("http://[::1]")
        )
        profile = UpstreamServerProfile(
            server_id=sid,
            name=str(entry.get("name") or raw_id),
            transport=transport,
            enabled=False,
            autostart=False,
            command=command,
            args=args,
            cwd=str(entry.get("cwd") or ""),
            env=plain_env,
            url=raw_url,
            auth_mode=auth_mode,
            allow_local_endpoint=allow_local,
            min_profile="allowlist",
            approved_by_owner=False,
            notes=f"Imported from {source_name}",
        )
        dup_id = _find_duplicate_server_id(profile, existing)
        if dup_id:
            warnings.append(f"Duplicate detected: server `{dup_id}` already configured.")
        out.append(
            ParsedImportCandidate(
                source_name=source_name,
                profile=profile,
                secret_env=secret_env,
                bearer_token=bearer_token,
                secret_headers=secret_headers,
                warnings=tuple(warnings),
                duplicate_of=dup_id,
            )
        )
    return out


def parse_config_file(path: Path, *, store: GatewayConfigStore | None = None, source_name: str = "") -> list[ParsedImportCandidate]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_config_text(
        text,
        filename=str(path),
        source_name=source_name or Path(path).name,
        store=store,
    )
