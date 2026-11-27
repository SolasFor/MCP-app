"""Workspace <-> Managed Server linkage, lossless v1.0.2 migration, and cross-layer authorization."""
from __future__ import annotations

import shutil
from dataclasses import dataclass, replace
from typing import Any, Literal

from app.platform import get_platform
from backend.servers.models import ServerProfile, validate_server_name
from backend.servers.store import SECRETS_NAMESPACE as SERVER_SECRETS_NS
from backend.servers.store import ServerConfigStore
from backend.workspaces.models import (
    SCHEMA_VERSION as WS_SCHEMA_VERSION,
    WorkspaceProfile,
    validate_workspace_id,
)
from backend.workspaces.store import WorkspaceStore

_PROFILE_RANK = {"safe": 0, "allowlist": 1, "full": 2}
_VALID_SERVER_MODES = ("read", "control")


@dataclass(frozen=True)
class WorkspaceServersSnapshot:
    """Consistent partitioned view of workspaces, linked servers, stale refs, and unlinked servers."""

    workspaces: dict[str, WorkspaceProfile]
    servers: dict[str, ServerProfile]
    server_to_workspaces: dict[str, list[str]]
    linked_by_workspace: dict[str, list[ServerProfile]]
    missing_by_workspace: dict[str, tuple[str, ...]]
    unlinked_servers: list[ServerProfile]


def _dedupe_preserve(items: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in items:
        clean = str(raw).strip()
        if clean and clean not in seen:
            seen.add(clean)
            out.append(clean)
    return tuple(out)


def _is_owner(client_id: str | None) -> bool:
    return client_id in (None, "", "owner")


def _workspace_allows_client(
    ws: WorkspaceProfile,
    *,
    client_id: str,
    client_profile: str,
    required_perms: tuple[str, ...],
) -> bool:
    if not ws.enabled:
        return False
    if _PROFILE_RANK.get(client_profile, 0) < _PROFILE_RANK.get(ws.min_profile, 1):
        return False
    if ws.allowed_clients and client_id not in ws.allowed_clients:
        return False
    return ws.permissions_for(client_id).allows(required_perms)


def _backup_once_with_acl(path, suffix: str) -> str:
    bak = path.with_suffix(suffix)
    if not bak.exists():
        shutil.copy2(path, bak)
        get_platform().restrict_path_acl(bak, is_dir=False)
    return str(bak)


def _assert_server_stopped(server_manager: Any, server_name: str, action: str) -> None:
    if server_manager is None:
        return
    try:
        st = server_manager.status_server(server_name, client_id="owner")
    except ValueError:
        return
    if st.get("running"):
        raise ValueError(f"Stop server {server_name!r} before {action}")


def _copy_server_secrets(
    server_store: ServerConfigStore,
    old_profile: ServerProfile,
    new_name: str,
) -> tuple[dict[str, str], list[str]]:
    new_refs: dict[str, str] = {}
    old_keys: list[str] = []
    for env_key, ref in old_profile.env_secret_refs.items():
        val = server_store.secret_store.resolve_ref(ref)
        if val is None:
            raise ValueError(f"Missing secret for {old_profile.name!r} env var {env_key!r}")
        new_refs[env_key] = server_store.set_env_secret(new_name, env_key, val)
        try:
            ns, old_key = server_store.secret_store.parse_ref(ref)
            if ns == SERVER_SECRETS_NS:
                old_keys.append(old_key)
        except Exception:  # noqa: BLE001
            pass
    return new_refs, old_keys


def _delete_old_server_secret_keys(server_store: ServerConfigStore, old_keys: list[str]) -> None:
    for old_key in old_keys:
        try:
            server_store.secret_store.delete_secret(SERVER_SECRETS_NS, old_key)
        except Exception:  # noqa: BLE001
            pass


def _rewrite_depends_on(profiles: dict[str, ServerProfile], old_name: str, new_name: str) -> None:
    for sname, prof in list(profiles.items()):
        if old_name not in prof.depends_on:
            continue
        profiles[sname] = replace(
            prof,
            depends_on=_dedupe_preserve([new_name if dep == old_name else dep for dep in prof.depends_on]),
        )


def _rewrite_workspace_links(workspace_store: WorkspaceStore, old_name: str, new_name: str) -> None:
    workspaces = workspace_store.load_workspaces()
    changed = False
    for wid, ws in list(workspaces.items()):
        if old_name not in ws.linked_servers:
            continue
        workspaces[wid] = replace(
            ws,
            linked_servers=_dedupe_preserve([new_name if s == old_name else s for s in ws.linked_servers]),
        )
        changed = True
    if changed:
        workspace_store.save_workspaces(workspaces)


def _authorize_owner_server_op(
    workspaces: dict[str, WorkspaceProfile],
    linked_wids: list[str],
    clean_srv: str,
    workspace_id: str,
) -> list[str]:
    if not workspace_id:
        return linked_wids
    clean_wid = validate_workspace_id(workspace_id)
    ws = workspaces.get(clean_wid)
    if ws is None or clean_srv not in ws.linked_servers:
        raise PermissionError(f"Server {clean_srv!r} is not linked to workspace {clean_wid!r}")
    return [clean_wid]


def _authorize_client_server_op(
    workspaces: dict[str, WorkspaceProfile],
    linked_wids: list[str],
    clean_srv: str,
    *,
    client_id: str,
    client_profile: str,
    required: tuple[str, ...],
    workspace_id: str,
) -> list[str]:
    if workspace_id:
        clean_wid = validate_workspace_id(workspace_id)
        ws = workspaces.get(clean_wid)
        if ws is None or clean_srv not in ws.linked_servers:
            raise PermissionError(f"Server {clean_srv!r} is not linked to workspace {clean_wid!r}")
        if not _workspace_allows_client(
            ws, client_id=client_id, client_profile=client_profile, required_perms=required
        ):
            raise PermissionError(f"Client {client_id!r} lacks workspace permissions for {clean_wid!r}")
        return [clean_wid]

    if not linked_wids:
        return []

    authorized = [
        wid
        for wid in linked_wids
        if _workspace_allows_client(
            workspaces[wid], client_id=client_id, client_profile=client_profile, required_perms=required
        )
    ]
    if not authorized:
        raise PermissionError(
            f"Client {client_id!r} lacks workspace permissions for linked server {clean_srv!r}"
        )
    return authorized


class WorkspaceServerCoordinator:
    """Single-source coordinator linking WorkspaceProfile.linked_servers to ServerConfigStore."""

    def __init__(
        self,
        workspace_store: WorkspaceStore,
        server_store: ServerConfigStore,
    ) -> None:
        self.workspace_store = workspace_store
        self.server_store = server_store

    def ensure_migrated(self) -> dict[str, Any]:
        """Idempotently normalize legacy v1.0.2 workspaces/servers schemas without auto-linking."""
        migrated_servers = False
        migrated_workspaces = False
        with self.workspace_store.lock(), self.server_store.lock():
            if self.server_store.path.is_file() and self.server_store.detect_schema_version() == 1:
                self.server_store.migrate_legacy_file(create_backup=True)
                migrated_servers = True

            if self.workspace_store.path.is_file():
                ws_version = self.workspace_store.detect_schema_version()
                workspaces = self.workspace_store.load_workspaces()
                if ws_version < WS_SCHEMA_VERSION:
                    _backup_once_with_acl(self.workspace_store.path, ".json.v1.bak")
                    self.workspace_store.save_workspaces(workspaces)
                    migrated_workspaces = True
            else:
                workspaces = {}

            servers = self.server_store.load_profiles(strict=False)
            return {
                "migrated_servers": migrated_servers,
                "migrated_workspaces": migrated_workspaces,
                "workspaces": len(workspaces),
                "servers": len(servers),
            }

    def partition_servers(self) -> WorkspaceServersSnapshot:
        """Return consistent workspace-linked and unlinked ServerProfile partitions."""
        with self.workspace_store.lock(), self.server_store.lock():
            workspaces = self.workspace_store.load_workspaces()
            servers = self.server_store.load_profiles(strict=False)
        server_to_workspaces: dict[str, list[str]] = {name: [] for name in servers}
        linked_by_workspace: dict[str, list[ServerProfile]] = {}
        missing_by_workspace: dict[str, tuple[str, ...]] = {}
        linked_names: set[str] = set()

        for wid in sorted(workspaces):
            ws = workspaces[wid]
            linked_list: list[ServerProfile] = []
            missing_list: list[str] = []
            for srv_name in ws.linked_servers:
                prof = servers.get(srv_name)
                if prof is None:
                    missing_list.append(srv_name)
                    continue
                linked_list.append(prof)
                linked_names.add(srv_name)
                server_to_workspaces.setdefault(srv_name, []).append(wid)
            linked_by_workspace[wid] = linked_list
            missing_by_workspace[wid] = tuple(missing_list)

        unlinked = [servers[name] for name in sorted(servers) if name not in linked_names]
        return WorkspaceServersSnapshot(
            workspaces=workspaces,
            servers=servers,
            server_to_workspaces=server_to_workspaces,
            linked_by_workspace=linked_by_workspace,
            missing_by_workspace=missing_by_workspace,
            unlinked_servers=unlinked,
        )

    def link_server(self, workspace_id: str, server_name: str) -> WorkspaceProfile:
        """Link an existing ServerProfile to a WorkspaceProfile without altering server privileges."""
        clean_wid = validate_workspace_id(workspace_id)
        clean_srv = validate_server_name(server_name)
        with self.workspace_store.lock(), self.server_store.lock():
            workspaces = self.workspace_store.load_workspaces()
            ws = workspaces.get(clean_wid)
            if ws is None:
                raise KeyError(f"Unknown workspace: {clean_wid!r}")
            servers = self.server_store.load_profiles(strict=True)
            if clean_srv not in servers:
                raise ValueError(f"Unknown server profile: {clean_srv!r}")
            if clean_srv in ws.linked_servers:
                return ws
            updated = replace(ws, linked_servers=_dedupe_preserve([*ws.linked_servers, clean_srv]))
            workspaces[clean_wid] = updated
            self.workspace_store.save_workspaces(workspaces)
            return updated

    def unlink_server(self, workspace_id: str, server_name: str) -> WorkspaceProfile:
        """Remove a server reference from WorkspaceProfile without stopping or deleting the server."""
        clean_wid = validate_workspace_id(workspace_id)
        clean_srv = validate_server_name(server_name)
        with self.workspace_store.lock():
            workspaces = self.workspace_store.load_workspaces()
            ws = workspaces.get(clean_wid)
            if ws is None:
                raise KeyError(f"Unknown workspace: {clean_wid!r}")
            new_links = tuple(s for s in ws.linked_servers if s != clean_srv)
            if new_links == ws.linked_servers:
                return ws
            updated = replace(ws, linked_servers=new_links)
            workspaces[clean_wid] = updated
            self.workspace_store.save_workspaces(workspaces)
            return updated

    def set_workspace_servers(self, workspace_id: str, server_names: tuple[str, ...] | list[str]) -> WorkspaceProfile:
        """Replace linked_servers on one workspace with deduplicated validated server names."""
        clean_wid = validate_workspace_id(workspace_id)
        normalized = _dedupe_preserve([validate_server_name(s) for s in server_names])
        with self.workspace_store.lock(), self.server_store.lock():
            workspaces = self.workspace_store.load_workspaces()
            ws = workspaces.get(clean_wid)
            if ws is None:
                raise KeyError(f"Unknown workspace: {clean_wid!r}")
            servers = self.server_store.load_profiles(strict=True)
            for sname in normalized:
                if sname not in servers and sname not in ws.linked_servers:
                    raise ValueError(f"Unknown server profile: {sname!r}")
            updated = replace(ws, linked_servers=normalized)
            workspaces[clean_wid] = updated
            self.workspace_store.save_workspaces(workspaces)
            return updated

    def delete_workspace_preserving_servers(self, workspace_id: str, *, delete_secrets: bool = True) -> bool:
        """Delete a workspace registry entry while preserving all managed server profiles and processes."""
        return self.workspace_store.delete_workspace(workspace_id, delete_secrets=delete_secrets)

    def delete_server_and_unlink(
        self,
        server_name: str,
        *,
        server_manager: Any = None,
        delete_secrets: bool = True,
    ) -> bool:
        """Delete a stopped, undepended server profile and remove stale links from all workspaces."""
        clean_srv = validate_server_name(server_name)
        _assert_server_stopped(server_manager, clean_srv, "deleting")
        with self.workspace_store.lock(), self.server_store.lock():
            deleted = self.server_store.delete_profile(clean_srv, delete_secrets=delete_secrets)
            if not deleted:
                return False
            workspaces = self.workspace_store.load_workspaces()
            changed = False
            for wid, ws in list(workspaces.items()):
                if clean_srv in ws.linked_servers:
                    workspaces[wid] = replace(
                        ws,
                        linked_servers=tuple(s for s in ws.linked_servers if s != clean_srv),
                    )
                    changed = True
            if changed:
                self.workspace_store.save_workspaces(workspaces)
            return True

    def rename_server(
        self,
        old_name: str,
        new_name: str,
        *,
        server_manager: Any = None,
    ) -> ServerProfile:
        """Rename a stopped server profile ID, updating secret refs, depends_on, and workspace links."""
        clean_old = validate_server_name(old_name)
        clean_new = validate_server_name(new_name)
        if clean_old == clean_new:
            raise ValueError("New server name must differ from current name")
        _assert_server_stopped(server_manager, clean_old, "renaming")

        with self.workspace_store.lock(), self.server_store.lock():
            profiles = self.server_store.load_profiles(strict=True)
            old_prof = profiles.get(clean_old)
            if old_prof is None:
                raise ValueError(f"Unknown server profile: {clean_old!r}")
            if clean_new in profiles:
                raise ValueError(f"Server '{clean_new}' already exists")

            new_refs, old_secret_keys = _copy_server_secrets(self.server_store, old_prof, clean_new)
            display = clean_new if old_prof.display_name == clean_old else old_prof.display_name
            renamed = replace(
                old_prof,
                name=clean_new,
                display_name=display,
                env_secret_refs=new_refs,
            )
            del profiles[clean_old]
            profiles[clean_new] = renamed
            _rewrite_depends_on(profiles, clean_old, clean_new)
            self.server_store.save_profiles(profiles)
            _delete_old_server_secret_keys(self.server_store, old_secret_keys)
            _rewrite_workspace_links(self.workspace_store, clean_old, clean_new)
            return renamed

    def authorize_server_operation(
        self,
        server_name: str,
        *,
        client_id: str | None,
        client_profile: str,
        mode: Literal["read", "control"] = "read",
        workspace_id: str = "",
    ) -> list[str]:
        """Fail-closed check intersecting caller permissions across linked workspaces."""
        if mode not in _VALID_SERVER_MODES:
            raise PermissionError(f"Invalid server access mode: {mode!r}")
        clean_srv = validate_server_name(server_name)
        try:
            with self.workspace_store.lock():
                workspaces = self.workspace_store.load_workspaces()
        except Exception as exc:  # noqa: BLE001
            raise PermissionError(f"Workspace authorization store unavailable: {type(exc).__name__}") from exc

        linked_wids = [wid for wid in sorted(workspaces) if clean_srv in workspaces[wid].linked_servers]
        if _is_owner(client_id):
            return _authorize_owner_server_op(workspaces, linked_wids, clean_srv, workspace_id)

        assert isinstance(client_id, str) and client_id
        required = ("read",) if mode == "read" else ("read", "execute")
        return _authorize_client_server_op(
            workspaces,
            linked_wids,
            clean_srv,
            client_id=client_id,
            client_profile=client_profile,
            required=required,
            workspace_id=workspace_id,
        )
