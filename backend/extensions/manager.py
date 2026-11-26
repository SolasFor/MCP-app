"""Lifecycle, verification, permissions, crash recovery, update/rollback, and catalog for Extensions."""
from __future__ import annotations

import json
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from app.core.redaction import SecretRedactor
from backend.extensions.models import (
    ALLOWED_EXTENSION_PERMISSIONS,
    ExtensionManifest,
    ExtensionRuntimeStatus,
    InstalledExtension,
    check_api_compatibility,
    validate_extension_id,
)
from backend.extensions.packaging import (
    MANIFEST_FILE,
    bytes_sha256,
    create_extension_zip,
    verify_and_extract_zip,
)
from backend.extensions.runtime import ExtensionProcessHost
from backend.extensions.store import ExtensionStore, official_extensions_dir


class ExtensionManager:
    """Orchestrates out-of-process extensions with fail-closed trust, permissions, and rollback."""

    def __init__(
        self,
        store: ExtensionStore | None = None,
        *,
        catalog_dir: Path | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self.store = store or ExtensionStore()
        self.catalog_dir = Path(catalog_dir) if catalog_dir is not None else official_extensions_dir()
        self._redactor = redactor or SecretRedactor()
        self._lock = threading.RLock()
        self._hosts: dict[str, ExtensionProcessHost] = {}
        self._register_all_secrets()

    def _register_all_secrets(self) -> None:
        for secret in self.store.collect_secret_values():
            self._redactor.register(secret)

    # ------------------------------------------------------------------ Catalog
    def list_catalog(self, query: str = "") -> list[dict[str, Any]]:
        """List official bundled extensions matching optional text query."""
        q = (query or "").strip().lower()
        installed = self.store.load_all()
        items: list[dict[str, Any]] = []
        if not self.catalog_dir.is_dir():
            return items
        for child in sorted(self.catalog_dir.iterdir()):
            manifest_path = child / MANIFEST_FILE
            if not child.is_dir() or not manifest_path.is_file():
                continue
            try:
                raw = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest = ExtensionManifest.from_dict(raw)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if manifest.id == "starter_template":
                continue
            if q and q not in manifest.id.lower() and q not in manifest.name.lower() and q not in manifest.description.lower():
                continue
            rec = installed.get(manifest.id)
            items.append({
                "id": manifest.id,
                "name": manifest.name,
                "version": manifest.version,
                "api_version": manifest.api_version,
                "description": manifest.description,
                "permissions": list(manifest.permissions),
                "tools": [t.name for t in manifest.tools],
                "installed": rec is not None,
                "installed_version": rec.manifest.version if rec is not None else "",
                "enabled": rec.enabled if rec is not None else False,
            })
        return items

    def list_extensions(self, query: str = "") -> list[dict[str, Any]]:
        """List installed extensions with live worker status."""
        q = (query or "").strip().lower()
        items: list[dict[str, Any]] = []
        for ext in self.store.load_all().values():
            if q and q not in ext.manifest.id.lower() and q not in ext.manifest.name.lower():
                continue
            st = self.status(ext.manifest.id)
            items.append({
                "id": ext.manifest.id,
                "name": ext.manifest.name,
                "version": ext.manifest.version,
                "api_version": ext.manifest.api_version,
                "description": ext.manifest.description,
                "official": ext.manifest.official,
                "enabled": ext.enabled,
                "source": ext.source,
                "verified_by": ext.verified_by,
                "package_sha256": ext.package_sha256,
                "requested_permissions": list(ext.manifest.permissions),
                "granted_permissions": list(ext.granted_permissions),
                "allowed_clients": list(ext.allowed_clients),
                "approved_tools": list(ext.approved_tools),
                "tools": [t.to_dict() for t in ext.manifest.tools],
                "ui_components": [c.to_dict() for c in ext.manifest.ui_components],
                "secret_keys": list(ext.manifest.secret_keys),
                "previous_version": ext.previous_version,
                "runtime": st.to_dict(),
            })
        return items

    def info(self, ext_id: str) -> dict[str, Any]:
        clean = validate_extension_id(ext_id)
        for item in self.list_extensions():
            if item["id"] == clean:
                return item
        raise KeyError(f"Extension not installed: {clean}")

    # ------------------------------------------------------------------ Install / Update / Rollback
    def install_zip(
        self,
        zip_path: Path,
        *,
        expected_sha256: str = "",
        owner_confirmed: bool = False,
        grant_permissions: tuple[str, ...] | None = None,
        enable_after_install: bool = False,
        allowed_clients: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        """Verify, check compatibility, extract, and register a packaged extension ZIP."""
        with self._lock:
            staging = self.store.base_dir / f".stage_{os.getpid()}_{int(time.time() * 1000)}"
            try:
                ver = verify_and_extract_zip(
                    Path(zip_path),
                    staging,
                    trusted_keys=self.store.trusted_keys(),
                    expected_sha256=expected_sha256,
                    owner_confirmed=owner_confirmed,
                )
                compat_ok, compat_msg = check_api_compatibility(ver.manifest.api_version)
                if not compat_ok:
                    raise ValueError(compat_msg)
                existing = self.store.get(ver.manifest.id)
                if existing is not None:
                    raise ValueError(f"Extension {ver.manifest.id!r} already installed; use update_zip()")

                target_dir = self.store.version_dir(ver.manifest.id, ver.manifest.version)
                self.store.copy_tree_clean(staging, target_dir)
                data_dir = self.store.data_dir(ver.manifest.id)
                granted = self._normalize_granted(ver.manifest, grant_permissions)
                now = time.time()
                rec = InstalledExtension(
                    manifest=ver.manifest,
                    enabled=False,
                    source="zip",
                    package_sha256=ver.package_sha256,
                    verified_by=ver.verified_by,
                    granted_permissions=granted,
                    allowed_clients=tuple(c.strip() for c in allowed_clients if c.strip()),
                    approved_tools=(),
                    install_dir=str(target_dir),
                    data_dir=str(data_dir),
                    previous_version="",
                    installed_at=now,
                    updated_at=now,
                )
                self.store.upsert(rec)
                self.store.append_log(
                    ver.manifest.id,
                    f"Installed v{ver.manifest.version} ({ver.verified_by}, sha256={ver.package_sha256[:12]})",
                    redactor=self._redactor,
                )
            finally:
                shutil.rmtree(staging, ignore_errors=True)

        if enable_after_install:
            self.enable(ver.manifest.id)
        return self.info(ver.manifest.id)

    def install_official(
        self,
        ext_id: str,
        *,
        grant_permissions: tuple[str, ...] | None = None,
        enable_after_install: bool = True,
    ) -> dict[str, Any]:
        """Install an official bundled extension from `extensions_official/` using verified packaging."""
        clean = validate_extension_id(ext_id)
        src_dir = (self.catalog_dir / clean).resolve()
        if not src_dir.is_dir() or not (src_dir / MANIFEST_FILE).is_file():
            raise KeyError(f"Official extension not found in catalog: {clean}")
        tmp_zip = self.store.base_dir / f".official_{clean}_{os.getpid()}.zip"
        try:
            sha = create_extension_zip(src_dir, tmp_zip)
            self.install_zip(
                tmp_zip,
                expected_sha256=sha,
                owner_confirmed=True,
                grant_permissions=grant_permissions if grant_permissions is not None else (),
                enable_after_install=False,
            )
            with self._lock:
                rec = self.store.get(clean)
                assert rec is not None
                rec.source = "official"
                rec.verified_by = f"official:{bytes_sha256(sha.encode('ascii'))[:12]}"
                if grant_permissions is None:
                    rec.granted_permissions = tuple(rec.manifest.permissions)
                self.store.upsert(rec)
        finally:
            tmp_zip.unlink(missing_ok=True)
        if enable_after_install:
            self.enable(clean)
        return self.info(clean)

    def update_zip(
        self,
        ext_id: str,
        zip_path: Path,
        *,
        expected_sha256: str = "",
        owner_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Update an existing extension while preserving its data directory and creating rollback backup."""
        clean = validate_extension_id(ext_id)
        with self._lock:
            existing = self.store.get(clean)
            if existing is None:
                raise KeyError(f"Extension not installed: {clean}")
            was_enabled = existing.enabled
            self._stop_host_locked(clean)

            staging = self.store.base_dir / f".stage_upd_{clean}_{os.getpid()}"
            try:
                ver = verify_and_extract_zip(
                    Path(zip_path),
                    staging,
                    trusted_keys=self.store.trusted_keys(),
                    expected_sha256=expected_sha256,
                    owner_confirmed=owner_confirmed,
                )
                if ver.manifest.id != clean:
                    raise ValueError(f"Update package id {ver.manifest.id!r} != {clean!r}")
                compat_ok, compat_msg = check_api_compatibility(ver.manifest.api_version)
                if not compat_ok:
                    raise ValueError(compat_msg)

                old_dir = Path(existing.install_dir)
                if old_dir.is_dir():
                    backup = self.store.backup_dir(clean, existing.manifest.version)
                    self.store.copy_tree_clean(old_dir, backup)

                new_dir = self.store.version_dir(clean, ver.manifest.version)
                self.store.copy_tree_clean(staging, new_dir)

                # Keep only previously granted permissions that still exist in new manifest.
                kept_perms = tuple(p for p in existing.granted_permissions if p in ver.manifest.permissions)
                rec = InstalledExtension(
                    manifest=ver.manifest,
                    enabled=was_enabled,
                    source=existing.source,
                    package_sha256=ver.package_sha256,
                    verified_by=ver.verified_by,
                    granted_permissions=kept_perms,
                    allowed_clients=existing.allowed_clients,
                    approved_tools=tuple(t for t in existing.approved_tools if any(mt.name == t for mt in ver.manifest.tools)),
                    install_dir=str(new_dir),
                    data_dir=existing.data_dir or str(self.store.data_dir(clean)),
                    previous_version=existing.manifest.version,
                    installed_at=existing.installed_at,
                    updated_at=time.time(),
                )
                self.store.upsert(rec)
                self.store.append_log(
                    clean,
                    f"Updated v{existing.manifest.version} -> v{ver.manifest.version}",
                    redactor=self._redactor,
                )
            finally:
                shutil.rmtree(staging, ignore_errors=True)

        if was_enabled:
            self.enable(clean)
        return self.info(clean)

    def rollback(self, ext_id: str) -> dict[str, Any]:
        """Restore the previous installed version from backup without losing `data/<id>`."""
        clean = validate_extension_id(ext_id)
        with self._lock:
            existing = self.store.get(clean)
            if existing is None:
                raise KeyError(f"Extension not installed: {clean}")
            if not existing.previous_version:
                raise RuntimeError("No previous version backup available for rollback")
            backup = self.store.backup_dir(clean, existing.previous_version)
            if not backup.is_dir() or not (backup / MANIFEST_FILE).is_file():
                raise RuntimeError("Backup directory missing or incomplete")
            was_enabled = existing.enabled
            self._stop_host_locked(clean)

            restored_manifest = ExtensionManifest.from_dict(
                json.loads((backup / MANIFEST_FILE).read_text(encoding="utf-8"))
            )
            restored_dir = self.store.version_dir(clean, restored_manifest.version)
            self.store.copy_tree_clean(backup, restored_dir)
            kept_perms = tuple(p for p in existing.granted_permissions if p in restored_manifest.permissions)
            rec = InstalledExtension(
                manifest=restored_manifest,
                enabled=was_enabled,
                source=existing.source,
                package_sha256=existing.package_sha256,
                verified_by=existing.verified_by,
                granted_permissions=kept_perms,
                allowed_clients=existing.allowed_clients,
                approved_tools=existing.approved_tools,
                install_dir=str(restored_dir),
                data_dir=existing.data_dir or str(self.store.data_dir(clean)),
                previous_version="",
                installed_at=existing.installed_at,
                updated_at=time.time(),
            )
            self.store.upsert(rec)
            self.store.append_log(clean, f"Rolled back to v{restored_manifest.version}", redactor=self._redactor)

        if was_enabled:
            self.enable(clean)
        return self.info(clean)

    def uninstall(self, ext_id: str, *, keep_data: bool = True) -> dict[str, Any]:
        clean = validate_extension_id(ext_id)
        with self._lock:
            self._stop_host_locked(clean)
            removed = self.store.remove(clean)
            if removed is None:
                raise KeyError(f"Extension not installed: {clean}")
            shutil.rmtree(self.store.installed_root / clean, ignore_errors=True)
            shutil.rmtree(self.store.backups_root / clean, ignore_errors=True)
            if not keep_data:
                shutil.rmtree(self.store.data_root / clean, ignore_errors=True)
            return {"id": clean, "uninstalled": True, "kept_data": keep_data}

    # ------------------------------------------------------------------ Permissions & Secrets
    @staticmethod
    def _normalize_granted(manifest: ExtensionManifest, requested: tuple[str, ...] | None) -> tuple[str, ...]:
        if requested is None:
            return ()
        valid: list[str] = []
        for perm in requested:
            if perm in manifest.permissions and perm in ALLOWED_EXTENSION_PERMISSIONS and perm not in valid:
                valid.append(perm)
        return tuple(valid)

    def set_permissions(
        self,
        ext_id: str,
        granted_permissions: tuple[str, ...],
        *,
        allowed_clients: tuple[str, ...] | None = None,
        approved_tools: tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        clean = validate_extension_id(ext_id)
        with self._lock:
            ext = self.store.get(clean)
            if ext is None:
                raise KeyError(f"Extension not installed: {clean}")
            ext.granted_permissions = self._normalize_granted(ext.manifest, granted_permissions)
            if allowed_clients is not None:
                ext.allowed_clients = tuple(c.strip() for c in allowed_clients if c.strip())
            if approved_tools is not None:
                valid_names = {t.name for t in ext.manifest.tools}
                ext.approved_tools = tuple(t for t in approved_tools if t in valid_names)
            ext.updated_at = time.time()
            self.store.upsert(ext)
            self.store.append_log(clean, f"Updated permissions={list(ext.granted_permissions)}", redactor=self._redactor)
        return self.info(clean)

    def set_secret(self, ext_id: str, key: str, value: str) -> str:
        clean = validate_extension_id(ext_id)
        ext = self.store.get(clean)
        if ext is None:
            raise KeyError(f"Extension not installed: {clean}")
        if key not in ext.manifest.secret_keys:
            raise ValueError(f"Undeclared secret key {key!r} for extension {clean!r}")
        ref = self.store.set_secret(clean, key, value)
        self._redactor.register(value)
        with self._lock:
            if ext.enabled:
                self._stop_host_locked(clean)
                self._ensure_host_started_locked(ext)
        return ref

    # ------------------------------------------------------------------ Lifecycle & Execution
    def _host_for_locked(self, ext: InstalledExtension) -> ExtensionProcessHost:
        cid = ext.manifest.id
        entry = (Path(ext.install_dir) / ext.manifest.entrypoint).resolve()
        if not entry.is_file():
            raise FileNotFoundError(f"Missing extension entrypoint: {entry}")
        secrets = self.store.get_declared_secrets(cid, ext.manifest.secret_keys)
        for v in secrets.values():
            self._redactor.register(v)
        existing = self._hosts.get(cid)
        if existing is None or existing.entrypoint != entry:
            if existing is not None:
                existing.stop()

            def _emit_log(line: str, eid: str = cid) -> None:
                self.store.append_log(eid, line, redactor=self._redactor)

            existing = ExtensionProcessHost(
                extension_id=cid,
                entrypoint=entry,
                data_dir=Path(ext.data_dir or self.store.data_dir(cid)),
                declared_secrets=secrets,
                on_log=_emit_log,
                redactor=self._redactor,
            )
            self._hosts[cid] = existing
        else:
            existing.declared_secrets = secrets
        return existing

    def _ensure_host_started_locked(self, ext: InstalledExtension) -> ExtensionProcessHost:
        host = self._host_for_locked(ext)
        if not host.is_alive():
            host.start()
        return host

    def _stop_host_locked(self, ext_id: str) -> None:
        host = self._hosts.pop(ext_id, None)
        if host is not None:
            host.stop()

    def enable(self, ext_id: str) -> dict[str, Any]:
        clean = validate_extension_id(ext_id)
        with self._lock:
            ext = self.store.get(clean)
            if ext is None:
                raise KeyError(f"Extension not installed: {clean}")
            ext.enabled = True
            ext.updated_at = time.time()
            self.store.upsert(ext)
            self._ensure_host_started_locked(ext)
            self.store.append_log(clean, "Extension enabled", redactor=self._redactor)
        return self.info(clean)

    def disable(self, ext_id: str) -> dict[str, Any]:
        clean = validate_extension_id(ext_id)
        with self._lock:
            ext = self.store.get(clean)
            if ext is None:
                raise KeyError(f"Extension not installed: {clean}")
            ext.enabled = False
            ext.updated_at = time.time()
            self.store.upsert(ext)
            self._stop_host_locked(clean)
            self.store.append_log(clean, "Extension disabled", redactor=self._redactor)
        return self.info(clean)

    def status(self, ext_id: str) -> ExtensionRuntimeStatus:
        clean = validate_extension_id(ext_id)
        with self._lock:
            ext = self.store.get(clean)
            if ext is None:
                raise KeyError(f"Extension not installed: {clean}")
            host = self._hosts.get(clean)
            if not ext.enabled:
                return ExtensionRuntimeStatus(extension_id=clean, state="disabled")
            if host is None:
                return ExtensionRuntimeStatus(extension_id=clean, state="stopped")
            if host.is_alive():
                return ExtensionRuntimeStatus(
                    extension_id=clean,
                    state="running",
                    pid=host.pid,
                    restarts=host.restarts,
                    last_error=host.last_error,
                )
            if host.has_crashed():
                return ExtensionRuntimeStatus(
                    extension_id=clean,
                    state="crashed",
                    restarts=host.restarts,
                    last_error=host.last_error or "Worker exited unexpectedly",
                )
            return ExtensionRuntimeStatus(
                extension_id=clean,
                state="stopped",
                restarts=host.restarts,
                last_error=host.last_error,
            )

    def get_ui(self, ext_id: str) -> dict[str, Any]:
        clean = validate_extension_id(ext_id)
        with self._lock:
            ext = self.store.get(clean)
            if ext is None:
                raise KeyError(f"Extension not installed: {clean}")
            dynamic: dict[str, Any] = {}
            if ext.enabled:
                host = self._ensure_host_started_locked(ext)
                dynamic = host.request("ui.describe", {}, timeout_seconds=5.0) or {}
            return {
                "extension_id": clean,
                "components": [c.to_dict() for c in ext.manifest.ui_components],
                "live": dynamic,
            }

    def get_logs(self, ext_id: str, *, tail: int = 100) -> list[str]:
        return self.store.read_logs(ext_id, tail=tail)

    def call_tool(
        self,
        ext_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        client_id: str = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        clean = validate_extension_id(ext_id)
        ext = self.store.get(clean)
        if ext is None:
            raise KeyError(f"Extension not installed: {clean}")
        if not ext.enabled:
            raise PermissionError(f"Extension {clean!r} is disabled")
        if client_id != "owner":
            if client_profile == "safe":
                raise PermissionError("Safe OAuth profile cannot invoke extension tools")
            if ext.manifest.min_profile == "full" and client_profile != "full":
                raise PermissionError(f"Extension {clean!r} requires full profile")
            if ext.allowed_clients and client_id not in ext.allowed_clients:
                raise PermissionError(f"Client {client_id!r} is not allowed for extension {clean!r}")

        tool_spec = next((t for t in ext.manifest.tools if t.name == tool_name), None)
        if tool_spec is None:
            raise KeyError(f"Tool {tool_name!r} is not declared by extension {clean!r}")
        if tool_spec.permission and tool_spec.permission not in ext.granted_permissions:
            raise PermissionError(
                f"Extension {clean!r} lacks owner permission {tool_spec.permission!r} for tool {tool_name!r}"
            )
        if client_id != "owner" and client_profile != "full":
            if not tool_spec.read_only and tool_name not in ext.approved_tools:
                raise PermissionError(
                    f"Mutating extension tool {tool_name!r} requires full profile or explicit owner tool approval"
                )

        with self._lock:
            host = self._ensure_host_started_locked(ext)
        try:
            raw = host.request(
                "call_tool",
                {"name": tool_name, "arguments": dict(arguments or {})},
                timeout_seconds=15.0,
            )
        except Exception:
            self.store.append_log(clean, f"Tool error in {tool_name}: {host.last_error}", redactor=self._redactor)
            raise
        sanitized = json.loads(self._redactor.redact_text(json.dumps({"result": raw}, ensure_ascii=False)))
        return {
            "extension_id": clean,
            "tool": tool_name,
            "result": sanitized["result"],
        }

    def shutdown_all(self) -> None:
        with self._lock:
            for host in list(self._hosts.values()):
                try:
                    host.stop()
                except Exception:  # noqa: BLE001
                    pass
            self._hosts.clear()
