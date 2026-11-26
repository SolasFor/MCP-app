"""Redacted ZIP diagnostic bundle exporter for MCP-app v1.0.0.

Includes strictly sanitized logs, app/agent versions, redacted settings,
backend & provider state, network/proxy diagnostics, and OAuth error summaries.
Never includes secrets, SQLite credential DBs, user documents, or screenshots.
"""
from __future__ import annotations

import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

from app import APP_NAME, __version__
from app.core.logging_manager import LOG_COMPONENTS, LoggingManager, get_logging_manager, parse_log_line
from app.core.redaction import SecretRedactor
from app.platform import get_platform

_SECRET_SUBSTRINGS = (
    "token",
    "secret",
    "password",
    "passwd",
    "authtoken",
    "credential",
    "private_key",
)


def _strip_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
        if not parts.scheme or not parts.hostname:
            return raw
        host_lit = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
        netloc = f"{host_lit}:{parts.port}" if parts.port else host_lit
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except ValueError:
        return ""


def _scrub_obj(value: Any, redactor: SecretRedactor) -> Any:
    cleaned = redactor.redact_mapping(value)
    if isinstance(cleaned, dict):
        out: dict[str, Any] = {}
        for k, v in cleaned.items():
            low = str(k).casefold()
            if any(marker in low for marker in _SECRET_SUBSTRINGS) and isinstance(v, str) and v:
                out[k] = "[REDACTED]"
            else:
                out[k] = _scrub_obj(v, redactor)
        return out
    if isinstance(cleaned, list):
        return [_scrub_obj(item, redactor) for item in cleaned]
    return cleaned


def _collect_agent_versions(manager: Any | None) -> dict[str, str]:
    versions: dict[str, str] = {}
    if manager is not None and hasattr(manager, "connections"):
        for pid, prov in getattr(manager.connections, "providers", {}).items():
            try:
                det = prov.detect()
                versions[str(pid)] = det.version or ("installed" if det.installed else "not_found")
            except Exception:  # noqa: BLE001
                versions[str(pid)] = "unknown"
    else:
        from app.paths import resolve_cloudflared

        versions["cloudflare"] = "found" if resolve_cloudflared() else "not_found"
    return versions


def _summarize_oauth_errors(logs_dir: Path, redactor: SecretRedactor) -> dict[str, Any]:
    oauth_log = logs_dir / "oauth.log"
    recent_errors: list[dict[str, str]] = []
    if oauth_log.is_file():
        try:
            tail = oauth_log.read_text(encoding="utf-8", errors="replace").splitlines()[-500:]
            for line in tail:
                parsed = parse_log_line(redactor.redact_text(line), fallback_component="oauth")
                if parsed["level"] in ("WARNING", "ERROR", "CRITICAL"):
                    recent_errors.append({
                        "timestamp": parsed["timestamp"],
                        "level": parsed["level"],
                        "event_code": parsed["event_code"],
                        "request_id": parsed["request_id"],
                        "message": parsed["message"],
                    })
        except OSError:
            pass
    return {
        "error_count": len(recent_errors),
        "recent_events": recent_errors[-50:],
        "oauth_db_included": False,
    }


def export_diagnostics_zip(
    dest_path: Path,
    *,
    components: Iterable[str] | None = None,
    settings: Any | None = None,
    manager: Any | None = None,
    logging_manager: LoggingManager | None = None,
    proxy_report: dict[str, Any] | None = None,
    network_report: dict[str, Any] | None = None,
    redactor: SecretRedactor | None = None,
) -> Path:
    """Create a redacted diagnostic ZIP bundle safe to share for troubleshooting."""
    lm = logging_manager or get_logging_manager()
    lm.flush(timeout=2.0)

    red = SecretRedactor()
    for s in getattr(lm.redactor, "_secrets", ()):
        red.register(s)
    if redactor is not None:
        for s in getattr(redactor, "_secrets", ()):
            red.register(s)
    if manager is not None:
        tok = getattr(manager, "token", "")
        if isinstance(tok, str) and tok:
            red.register(tok)
        if hasattr(manager, "connections"):
            try:
                for sec in manager.connections.collect_secret_values():
                    red.register(sec)
            except Exception:  # noqa: BLE001
                pass

    selected = [c for c in (components or LOG_COMPONENTS) if c in LOG_COMPONENTS]
    if not selected:
        selected = list(LOG_COMPONENTS)

    try:
        from PyQt6.QtCore import PYQT_VERSION_STR

        qt_ver = PYQT_VERSION_STR
    except Exception:  # noqa: BLE001
        qt_ver = "unavailable"

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "app_name": APP_NAME,
        "app_version": __version__,
        "platform": sys.platform,
        "python_version": sys.version.split()[0],
        "qt_version": qt_ver,
        "capabilities": get_platform().capabilities(),
        "included_components": selected,
        "secrets_included": False,
        "oauth_db_included": False,
        "screenshots_included": False,
        "user_documents_included": False,
    }

    versions = {
        "app_version": __version__,
        "python_version": sys.version.split()[0],
        "qt_version": qt_ver,
        "transport_agents": _collect_agent_versions(manager),
    }

    settings_data: dict[str, Any] = {}
    if settings is not None:
        from dataclasses import asdict, is_dataclass

        settings_data = (
            asdict(settings)
            if (is_dataclass(settings) and not isinstance(settings, type))
            else dict(vars(settings))
        )
    try:
        from app.core import proxy as px

        p_cfg = px.load()
        proxy_cfg_safe = {
            "mode": getattr(p_cfg, "mode", "none"),
            "enabled": bool(getattr(p_cfg, "enabled", False)),
            "url": _strip_url(str(getattr(p_cfg, "url", ""))),
            "hosts": list(getattr(p_cfg, "hosts", [])),
            "has_credentials": bool(getattr(p_cfg, "username", "") or getattr(p_cfg, "password", "")),
        }
    except Exception:  # noqa: BLE001
        proxy_cfg_safe = {}

    settings_redacted = {
        "app": _scrub_obj(settings_data, red),
        "proxy": _scrub_obj(proxy_cfg_safe, red),
    }

    backend_state: dict[str, Any] = {}
    providers_state: dict[str, Any] = {}
    if manager is not None:
        backend_state = {
            "overall": getattr(getattr(manager, "overall", None), "value", str(getattr(manager, "overall", ""))),
            "active_provider": getattr(manager, "active_provider", ""),
            "server_state": getattr(getattr(getattr(manager, "server", None), "state", None), "value", ""),
            "tunnel_state": getattr(getattr(getattr(manager, "tunnel", None), "state", None), "value", ""),
            "public_url": _strip_url(red.redact_text(str(getattr(manager, "public_url", "")))),
            "tunnel_protocol": getattr(manager, "tunnel_protocol", ""),
            "proxy_enabled": bool(getattr(manager, "proxy_enabled", False)),
        }
        if hasattr(manager, "connections"):
            try:
                raw_statuses = manager.connections.list_statuses(
                    local_host="127.0.0.1",
                    local_port=int(getattr(getattr(manager, "settings", None), "server_port", 8000)),
                    mcp_path=str(getattr(getattr(manager, "settings", None), "mcp_path", "/mcp")),
                    runtime_url=str(getattr(manager, "public_url", "")),
                    running=backend_state.get("overall") == "running",
                    refresh_detection=False,
                )
                providers_state = _scrub_obj(raw_statuses, red)
            except Exception:  # noqa: BLE001
                providers_state = {}

    if network_report is None and manager is not None and getattr(manager, "_diagnosis", None) is not None:
        diag = manager._diagnosis
        network_report = {
            "reachable": bool(getattr(diag, "reachable", False)),
            "summary": red.redact_text(str(getattr(diag, "summary", ""))),
            "advice": [red.redact_text(str(a)) for a in getattr(diag, "advice", ())],
        }

    if proxy_report is None:
        proxy_log = lm.component_path("proxy")
        proxy_tail: list[str] = []
        if proxy_log.is_file():
            try:
                proxy_tail = [red.redact_text(ln) for ln in proxy_log.read_text(encoding="utf-8", errors="replace").splitlines()[-50:]]
            except OSError:
                pass
        proxy_report = {"proxy_config": proxy_cfg_safe, "recent_proxy_events": proxy_tail}

    oauth_summary = _summarize_oauth_errors(lm.base_dir, red)

    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f".{dest.name}.{os.getpid()}.tmp")
    try:
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for filename, obj in (
                ("manifest.json", manifest),
                ("versions.json", versions),
                ("settings_redacted.json", settings_redacted),
                ("backend_state.json", backend_state),
                ("providers_state.json", providers_state),
                ("network_diagnostics.json", _scrub_obj(network_report or {}, red)),
                ("oauth_errors.json", _scrub_obj(oauth_summary, red)),
                ("proxy_diagnostics.json", _scrub_obj(proxy_report, red)),
            ):
                zf.writestr(filename, red.redact_text(json.dumps(obj, ensure_ascii=False, indent=2)))

            for comp in selected:
                p = lm.component_path(comp)
                if not p.is_file():
                    continue
                try:
                    raw_lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                cleaned = "\n".join(red.redact_text(line) for line in raw_lines)
                zf.writestr(f"logs/{comp}.log", cleaned + ("\n" if cleaned else ""))
        os.replace(tmp, dest)
        get_platform().restrict_path_acl(dest, is_dir=False)
        return dest
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
