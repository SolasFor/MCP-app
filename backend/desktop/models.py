"""Domain models, security policy, and atomic store for Computer Use (v0.9.6)."""
from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from app.platform import get_platform

SCHEMA_VERSION = 1
MAX_SCREENSHOT_BYTES = 1_500_000
DEFAULT_MAX_IMAGE_WIDTH = 1280
MAX_UI_TREE_DEPTH = 6
MAX_UI_TREE_NODES = 250
MAX_WAIT_TIMEOUT_S = 30.0
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
DESKTOP_MIN_PROFILES = ("allowlist", "full")
_PROFILE_RANK = {"safe": 0, "allowlist": 1, "full": 2}

SENSITIVE_TITLE_KEYWORDS = (
    "1password",
    "keepass",
    "bitwarden",
    "credential",
    "password",
    "passkey",
    "учетн",
    "пароль",
    "windows security",
    "безопасность windows",
    "user account control",
    "контроль учетных записей",
)


@dataclass(frozen=True)
class DesktopPolicy:
    """Owner-controlled opt-in boundaries for Windows interactive session access."""

    enabled: bool = False
    allow_screen_capture: bool = False
    allow_input_control: bool = False
    allow_secret_typing: bool = False
    allowed_clients: tuple[str, ...] = ()
    min_profile: str = "allowlist"
    allowed_apps: tuple[str, ...] = ()
    blocked_title_patterns: tuple[str, ...] = ()
    max_image_width: int = DEFAULT_MAX_IMAGE_WIDTH
    max_image_bytes: int = MAX_SCREENSHOT_BYTES
    emergency_stop: bool = False
    emergency_reason: str = ""

    def validate(self) -> None:
        if self.min_profile not in DESKTOP_MIN_PROFILES:
            raise ValueError(f"Invalid min_profile: {self.min_profile!r}")
        for cid in self.allowed_clients:
            if not CLIENT_ID_RE.fullmatch(cid):
                raise ValueError(f"Invalid allowed client_id: {cid!r}")
        for item in (*self.allowed_apps, *self.blocked_title_patterns):
            if not isinstance(item, str) or not item.strip() or "\x00" in item:
                raise ValueError("Invalid desktop app/title rule")
        if not (320 <= int(self.max_image_width) <= 3840):
            raise ValueError("max_image_width must be between 320 and 3840")
        if not (65_536 <= int(self.max_image_bytes) <= 4_000_000):
            raise ValueError("max_image_bytes must be between 65536 and 4000000")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "enabled": bool(self.enabled),
            "allow_screen_capture": bool(self.allow_screen_capture),
            "allow_input_control": bool(self.allow_input_control),
            "allow_secret_typing": bool(self.allow_secret_typing),
            "allowed_clients": list(self.allowed_clients),
            "min_profile": self.min_profile,
            "allowed_apps": list(self.allowed_apps),
            "blocked_title_patterns": list(self.blocked_title_patterns),
            "max_image_width": int(self.max_image_width),
            "max_image_bytes": int(self.max_image_bytes),
            "emergency_stop": bool(self.emergency_stop),
            "emergency_reason": self.emergency_reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> DesktopPolicy:
        if not isinstance(data, dict):
            return cls()
        pol = cls(
            enabled=bool(data.get("enabled", False)),
            allow_screen_capture=bool(data.get("allow_screen_capture", False)),
            allow_input_control=bool(data.get("allow_input_control", False)),
            allow_secret_typing=bool(data.get("allow_secret_typing", False)),
            allowed_clients=tuple(str(c).strip() for c in (data.get("allowed_clients") or ()) if str(c).strip()),
            min_profile=str(data.get("min_profile") or "allowlist").strip() or "allowlist",
            allowed_apps=tuple(str(a).strip() for a in (data.get("allowed_apps") or ()) if str(a).strip()),
            blocked_title_patterns=tuple(
                str(p).strip() for p in (data.get("blocked_title_patterns") or ()) if str(p).strip()
            ),
            max_image_width=int(data.get("max_image_width", DEFAULT_MAX_IMAGE_WIDTH)),
            max_image_bytes=int(data.get("max_image_bytes", MAX_SCREENSHOT_BYTES)),
            emergency_stop=bool(data.get("emergency_stop", False)),
            emergency_reason=str(data.get("emergency_reason") or "").strip(),
        )
        pol.validate()
        return pol


@dataclass(frozen=True)
class SessionState:
    interactive: bool
    locked: bool
    secure_desktop: bool
    desktop_name: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "interactive": self.interactive,
            "locked": self.locked,
            "secure_desktop": self.secure_desktop,
            "desktop_name": self.desktop_name,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class MonitorInfo:
    index: int
    name: str
    primary: bool
    x: int
    y: int
    width: int
    height: int
    work_x: int
    work_y: int
    work_width: int
    work_height: int
    dpi_x: int = 96
    dpi_y: int = 96

    @property
    def scale_percent(self) -> int:
        return int(round((self.dpi_x / 96.0) * 100)) if self.dpi_x > 0 else 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "primary": self.primary,
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "work_area": {
                "x": self.work_x,
                "y": self.work_y,
                "width": self.work_width,
                "height": self.work_height,
            },
            "dpi_x": self.dpi_x,
            "dpi_y": self.dpi_y,
            "scale_percent": self.scale_percent,
        }


@dataclass(frozen=True)
class WindowInfo:
    hwnd: int
    title: str
    class_name: str
    pid: int
    process_name: str
    x: int
    y: int
    width: int
    height: int
    minimized: bool = False
    active: bool = False
    elevated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "hwnd": self.hwnd,
            "title": self.title,
            "class_name": self.class_name,
            "pid": self.pid,
            "process_name": self.process_name,
            "bounds": {"x": self.x, "y": self.y, "width": self.width, "height": self.height},
            "minimized": self.minimized,
            "active": self.active,
            "elevated": self.elevated,
        }


@dataclass(frozen=True)
class UIElementNode:
    control_type: str
    name: str
    automation_id: str
    class_name: str
    bounds: dict[str, int]
    enabled: bool
    offscreen: bool
    is_password: bool
    hwnd: int
    pid: int
    children: tuple[UIElementNode, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_type": self.control_type,
            "name": "[REDACTED PASSWORD FIELD]" if self.is_password else self.name,
            "automation_id": self.automation_id,
            "class_name": self.class_name,
            "bounds": dict(self.bounds),
            "enabled": self.enabled,
            "offscreen": self.offscreen,
            "is_password": self.is_password,
            "hwnd": self.hwnd,
            "pid": self.pid,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass(frozen=True)
class ScreenshotResult:
    png_bytes: bytes
    width: int
    height: int
    scale_percent: int
    source: str
    monitor_index: int | None = None
    hwnd: int | None = None

    def metadata(self) -> dict[str, Any]:
        return {
            "width": self.width,
            "height": self.height,
            "size_bytes": len(self.png_bytes),
            "mime_type": "image/png",
            "scale_percent": self.scale_percent,
            "source": self.source,
            "monitor_index": self.monitor_index,
            "hwnd": self.hwnd,
            "saved_to_disk": False,
        }


class DesktopPolicyStore:
    """Thread-safe atomic store for Computer Use policy and live visual activity beacon."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.activity_path = self.path.with_name("activity.json")
        self._lock = threading.RLock()
        self._platform = get_platform()

    def load(self) -> DesktopPolicy:
        with self._lock:
            if not self.path.is_file():
                return DesktopPolicy()
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8-sig"))
                return DesktopPolicy.from_dict(raw if isinstance(raw, dict) else None)
            except (OSError, ValueError):
                return DesktopPolicy()

    def save(self, policy: DesktopPolicy) -> None:
        policy.validate()
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._platform.restrict_path_acl(self.path.parent, is_dir=True)
            tmp = self.path.with_suffix(".json.tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(policy.to_dict(), fh, indent=2, ensure_ascii=False)
            os.replace(tmp, self.path)
            self._platform.restrict_path_acl(self.path, is_dir=False)

    def update(self, **changes: Any) -> DesktopPolicy:
        """Atomically update selected fields while preserving min_profile, lists, and emergency_stop."""
        with self._lock:
            cur = self.load()
            updated = replace(cur, **changes)
            self.save(updated)
            return updated

    def set_emergency_stop(self, active: bool, reason: str = "") -> DesktopPolicy:
        with self._lock:
            cur = self.load()
            updated = DesktopPolicy(
                enabled=False if active else cur.enabled,
                allow_screen_capture=cur.allow_screen_capture,
                allow_input_control=cur.allow_input_control,
                allow_secret_typing=cur.allow_secret_typing,
                allowed_clients=cur.allowed_clients,
                min_profile=cur.min_profile,
                allowed_apps=cur.allowed_apps,
                blocked_title_patterns=cur.blocked_title_patterns,
                max_image_width=cur.max_image_width,
                max_image_bytes=cur.max_image_bytes,
                emergency_stop=active,
                emergency_reason=reason if active else "",
            )
            self.save(updated)
            if active:
                self.set_activity(False)
            return updated

    def set_activity(self, active: bool, *, client_id: str = "", tool: str = "") -> None:
        with self._lock:
            try:
                self.activity_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.activity_path.with_suffix(".act.tmp")
                payload = {
                    "active": bool(active),
                    "client_id": client_id,
                    "tool": tool,
                    "updated_at": time.time(),
                }
                tmp.write_text(json.dumps(payload), encoding="utf-8")
                os.replace(tmp, self.activity_path)
            except OSError:
                pass

    def read_activity(self) -> dict[str, Any]:
        with self._lock:
            if not self.activity_path.is_file():
                return {"active": False, "client_id": "", "tool": "", "updated_at": 0.0}
            try:
                data = json.loads(self.activity_path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    return {"active": False, "client_id": "", "tool": "", "updated_at": 0.0}
                updated = float(data.get("updated_at") or 0.0)
                stale = (time.time() - updated) > 15.0
                return {
                    "active": bool(data.get("active", False)) and not stale,
                    "client_id": str(data.get("client_id") or ""),
                    "tool": str(data.get("tool") or ""),
                    "updated_at": updated,
                }
            except (OSError, ValueError):
                return {"active": False, "client_id": "", "tool": "", "updated_at": 0.0}


def record_desktop_policy_audit(
    audit_path: Path,
    old_policy: DesktopPolicy,
    new_policy: DesktopPolicy,
    *,
    actor: str = "owner",
) -> None:
    """Append a tamper-resistant protected JSONL audit entry for Computer Use policy edits."""
    changed = {
        field_name: {"old": getattr(old_policy, field_name), "new": getattr(new_policy, field_name)}
        for field_name in (
            "enabled",
            "allow_screen_capture",
            "allow_input_control",
            "allow_secret_typing",
            "allowed_clients",
            "allowed_apps",
            "min_profile",
            "emergency_stop",
        )
        if getattr(old_policy, field_name) != getattr(new_policy, field_name)
    }
    if not changed:
        return
    entry = {
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "actor": actor,
        "changes": changed,
    }
    target = Path(audit_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    get_platform().restrict_path_acl(target.parent, is_dir=True)
    with open(target, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
    get_platform().restrict_path_acl(target, is_dir=False)


def desktop_tool_permissions(
    policy: DesktopPolicy | None,
    client_id: str | None,
    client_profile: str,
    *,
    emergency_stopped: bool = False,
) -> tuple[bool, bool]:
    """Return ``(allow_view, allow_control)`` for an OAuth client under live Computer Use policy."""
    if emergency_stopped or policy is None or policy.emergency_stop or not policy.enabled:
        return (False, False)
    if client_id not in (None, "", "owner"):
        if client_id == "mcp-app-user" or client_profile == "safe":
            return (False, False)
        if _PROFILE_RANK.get(client_profile, 0) < _PROFILE_RANK.get(policy.min_profile, 1):
            return (False, False)
        if policy.allowed_clients and client_id not in policy.allowed_clients:
            return (False, False)
    return (bool(policy.allow_screen_capture), bool(policy.allow_input_control))


def effective_desktop_access(
    policy: DesktopPolicy | None,
    client_id: str | None,
    client_profile: str,
    *,
    emergency_stopped: bool = False,
) -> Literal["disabled", "view", "control"]:
    """Return effective Computer Use capability level (``disabled``, ``view``, or ``control``)."""
    allow_view, allow_control = desktop_tool_permissions(
        policy, client_id, client_profile, emergency_stopped=emergency_stopped
    )
    if allow_control:
        return "control"
    if allow_view:
        return "view"
    return "disabled"
