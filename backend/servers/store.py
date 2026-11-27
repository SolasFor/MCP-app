"""Persistent v2 server store, lossless v1 migration, DPAPI SecretStore refs, and dependency DAG."""
from __future__ import annotations

import json
import shutil
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from app.core.atomic_io import atomic_write_json, cross_process_lock
from app.core.secret_store import SecretStore
from app.platform import get_platform
from backend.servers.models import (
    MAX_CONFIG_BYTES,
    MAX_SERVERS,
    SCHEMA_VERSION,
    ServerProfile,
    validate_server_name,
)

SECRETS_NAMESPACE = "servers"


def validate_dependencies(profiles: Mapping[str, ServerProfile]) -> None:
    """Verify every `depends_on` target exists and the dependency graph is acyclic."""
    for name, prof in profiles.items():
        for dep in prof.depends_on:
            if dep == name:
                raise ValueError(f"Dependency cycle detected: {name} -> {name}")
            if dep not in profiles:
                raise ValueError(f"Server {name!r} depends on unknown server {dep!r}")

    state: dict[str, int] = {}  # 0=unvisited, 1=visiting, 2=visited
    stack: list[str] = []

    def dfs(node: str) -> None:
        cur = state.get(node, 0)
        if cur == 1:
            idx = stack.index(node)
            cycle = " -> ".join([*stack[idx:], node])
            raise ValueError(f"Dependency cycle detected: {cycle}")
        if cur == 2:
            return
        state[node] = 1
        stack.append(node)
        for dep in profiles[node].depends_on:
            dfs(dep)
        stack.pop()
        state[node] = 2

    for name in profiles:
        if state.get(name, 0) == 0:
            dfs(name)


def resolve_start_order(profiles: Mapping[str, ServerProfile], target_name: str) -> list[str]:
    """Return topological dependency-first startup order ending with `target_name`."""
    validate_server_name(target_name)
    if target_name not in profiles:
        raise ValueError("Unknown server profile")
    validate_dependencies(profiles)

    order: list[str] = []
    seen: set[str] = set()

    def visit(node: str) -> None:
        if node in seen:
            return
        for dep in profiles[node].depends_on:
            visit(dep)
        seen.add(node)
        order.append(node)

    visit(target_name)
    return order


class ServerConfigStore:
    """Thread-safe store supporting legacy v1 managed_servers.json and encrypted secret refs."""

    def __init__(self, path: Path, secret_store: SecretStore | None = None) -> None:
        self.path = Path(path)
        self.secret_store = secret_store or SecretStore(self.path.parent / "secrets")
        self._lock = threading.RLock()
        self._platform = get_platform()

    def lock(self, timeout: float = 10.0):
        """Return a thread-reentrant cross-process lock covering this server store."""
        return cross_process_lock(self.path.with_name(".managed_servers.lock"), timeout=timeout)

    def _read_raw_document(self, source: Path | None = None) -> tuple[int, dict[str, Any]]:
        target = source or self.path
        if not target.exists():
            return SCHEMA_VERSION, {}
        with target.open(encoding="utf-8-sig") as fh:
            raw = fh.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise ValueError("Managed server configuration is too large")
        if not raw.strip():
            return SCHEMA_VERSION, {}
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Invalid managed server configuration")

        if "servers" in parsed and "schema_version" in parsed and isinstance(parsed.get("servers"), dict):
            version = int(parsed.get("schema_version") or SCHEMA_VERSION)
            servers_map = parsed["servers"]
        else:
            # Legacy v1 format: flat {name: {"argv": [...], "cwd": ..., "lifecycle": ...}}
            version = 1
            servers_map = parsed

        if not isinstance(servers_map, dict) or len(servers_map) > MAX_SERVERS:
            raise ValueError("Invalid managed server configuration")
        return version, servers_map

    def detect_schema_version(self) -> int:
        with self._lock:
            version, _ = self._read_raw_document()
            return version

    def load_profiles(self, *, strict: bool = True) -> dict[str, ServerProfile]:
        with self._lock:
            _version, raw_map = self._read_raw_document()
            profiles: dict[str, ServerProfile] = {}
            for name, entry in raw_map.items():
                if not isinstance(name, str) or not isinstance(entry, dict):
                    if strict:
                        raise ValueError("Invalid managed server configuration")
                    continue
                profiles[name] = ServerProfile.from_dict(name, entry)
            if strict:
                validate_dependencies(profiles)
            return profiles

    def get_profile(self, name: str) -> ServerProfile | None:
        validate_server_name(name)
        return self.load_profiles(strict=True).get(name)

    def save_profiles(self, profiles: Mapping[str, ServerProfile]) -> None:
        with self._lock, self.lock():
            if len(profiles) > MAX_SERVERS:
                raise ValueError(f"Server count exceeds maximum ({MAX_SERVERS})")
            for name, prof in profiles.items():
                if prof.name != name:
                    raise ValueError(f"Server key {name!r} does not match profile name {prof.name!r}")
                prof.validate()
            validate_dependencies(profiles)

            payload = {
                "schema_version": SCHEMA_VERSION,
                "servers": {
                    name: profiles[name].to_dict()
                    for name in sorted(profiles)
                },
            }
            atomic_write_json(self.path, payload, indent=2, restrict_acl=True)

    def upsert_profile(self, profile: ServerProfile) -> None:
        profile.validate()
        with self._lock, self.lock():
            profiles = self.load_profiles(strict=True)
            profiles[profile.name] = profile
            self.save_profiles(profiles)

    def delete_profile(self, name: str, *, delete_secrets: bool = True) -> bool:
        clean = validate_server_name(name)
        with self._lock, self.lock():
            profiles = self.load_profiles(strict=True)
            removed = profiles.pop(clean, None)
            if removed is None:
                return False
            # Refuse deleting a server still referenced by dependents so config stays valid.
            dependents = [
                other.name for other in profiles.values() if clean in other.depends_on
            ]
            if dependents:
                raise ValueError(
                    f"Cannot delete {clean!r}: depended on by {', '.join(sorted(dependents))}"
                )
            self.save_profiles(profiles)
            if delete_secrets:
                for ref in removed.env_secret_refs.values():
                    try:
                        ns, key = self.secret_store.parse_ref(ref)
                        if ns == SECRETS_NAMESPACE:
                            self.secret_store.delete_secret(ns, key)
                    except Exception:  # noqa: BLE001
                        pass
            return True

    def migrate_legacy_file(
        self,
        legacy_path: Path | None = None,
        *,
        create_backup: bool = True,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Losslessly import legacy v1 managed_servers.json into this v2 store."""
        source = Path(legacy_path) if legacy_path is not None else self.path
        if not source.is_file():
            return {"imported": [], "skipped": [], "total": 0, "backup_path": ""}

        with self._lock, self.lock():
            src_version, raw_map = self._read_raw_document(source)
            in_place = source.resolve() == self.path.resolve()
            existing = {} if (in_place and src_version == 1) else (
                self.load_profiles(strict=True) if self.path.exists() else {}
            )
            imported: list[str] = []
            skipped: list[str] = []

            backup_path = ""
            if create_backup and in_place and src_version == 1:
                bak = source.with_suffix(".json.v1.bak")
                shutil.copy2(source, bak)
                self._platform.restrict_path_acl(bak, is_dir=False)
                backup_path = str(bak)

            for name, entry in raw_map.items():
                if not isinstance(name, str) or not isinstance(entry, dict):
                    continue
                profile = ServerProfile.from_dict(name, entry)
                if name in existing and not (overwrite or (in_place and src_version == 1)):
                    skipped.append(name)
                    continue
                existing[name] = profile
                imported.append(name)

            self.save_profiles(existing)
            return {
                "imported": sorted(imported),
                "skipped": sorted(skipped),
                "total": len(existing),
                "source_version": src_version,
                "backup_path": backup_path,
            }

    def set_env_secret(self, server_name: str, env_key: str, value: str) -> str:
        clean_name = validate_server_name(server_name)
        if not env_key or not isinstance(env_key, str):
            raise ValueError("Invalid secret env key")
        secret_key = f"{clean_name}__{env_key}"
        self.secret_store.set_secret(SECRETS_NAMESPACE, secret_key, value)
        return self.secret_store.secret_ref(SECRETS_NAMESPACE, secret_key)

    def resolve_profile_env(self, profile: ServerProfile) -> tuple[dict[str, str], list[str]]:
        merged = dict(profile.env)
        secret_values: list[str] = []
        for key, ref in profile.env_secret_refs.items():
            val = self.secret_store.resolve_ref(ref)
            if val is None:
                raise ValueError(f"Missing secret for {profile.name} env var {key}")
            merged[key] = val
            if val:
                secret_values.append(val)
        return merged, secret_values

    def collect_secret_values(self) -> list[str]:
        values: list[str] = []
        with self._lock:
            try:
                profiles = self.load_profiles(strict=False)
            except Exception:  # noqa: BLE001
                return values
            for prof in profiles.values():
                for ref in prof.env_secret_refs.values():
                    try:
                        val = self.secret_store.resolve_ref(ref)
                        if val:
                            values.append(val)
                    except Exception:  # noqa: BLE001
                        pass
        return values

    def export_redacted(self) -> dict[str, Any]:
        """Export profiles without plaintext secrets (refs preserved as metadata only)."""
        profiles = self.load_profiles(strict=False)
        return {
            "schema_version": SCHEMA_VERSION,
            "servers": {name: profiles[name].to_dict() for name in sorted(profiles)},
        }
