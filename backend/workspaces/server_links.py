"""Workspace <-> Managed Server linkage, transactional config updates, and cross-layer authorization."""
from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable, Iterable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

from app.core.atomic_io import atomic_write_json, atomic_write_text, cross_process_lock, is_reparse_or_symlink
from app.core.secret_store import SecretStore
from app.platform import get_platform
from backend.servers.models import ServerProfile, validate_server_name
from backend.servers.store import SECRETS_NAMESPACE as SERVER_SECRETS_NS
from backend.servers.store import SCHEMA_VERSION as SRV_SCHEMA_VERSION
from backend.servers.store import ServerConfigStore
from backend.workspaces.discovery import (
    WizardAdditionPreview,
    WizardConflictError,
    WizardPlanSnapshot,
    WizardStalePlanError,
    compute_registry_fingerprint,
    compute_root_identity,
    verify_manifest_digests,
)
from backend.workspaces.models import (
    SCHEMA_VERSION as WS_SCHEMA_VERSION,
    WorkspaceProfile,
    validate_workspace_id,
)
from backend.workspaces.path_security import canonical_workspace_root
from backend.workspaces.store import SECRETS_NAMESPACE as WS_SECRETS_NS
from backend.workspaces.store import WorkspaceStore

_PROFILE_RANK = {"safe": 0, "allowlist": 1, "full": 2}
_VALID_SERVER_MODES = ("read", "control")
_TX_FILENAME = ".n03_coordinator_tx.json"
_SCHEDULES_FILENAME = "schedules.json"
_AUTOMATION_LOCK_FILENAME = ".automation.lock"
_MAX_TX_JOURNAL_BYTES = 16 * 1024 * 1024
_MAX_PREIMAGE_FILE_BYTES = 8 * 1024 * 1024
_MAX_MARKER_BYTES = 256
_TX_TOP_KEYS = frozenset({"schema_version", "files", "created_secrets"})


@dataclass(frozen=True)
class WorkspaceServersSnapshot:
    """Consistent partitioned view of workspaces, linked servers, stale refs, and unlinked servers."""

    workspaces: dict[str, WorkspaceProfile]
    servers: dict[str, ServerProfile]
    server_to_workspaces: dict[str, list[str]]
    linked_by_workspace: dict[str, list[ServerProfile]]
    missing_by_workspace: dict[str, tuple[str, ...]]
    unlinked_servers: list[ServerProfile]


@dataclass
class _TxMutationPlan:
    files_to_watch: tuple[Path, ...]
    new_secrets: list[tuple[str, str, str]] = None  # type: ignore[assignment]
    retire_secrets: list[tuple[str, str]] = None  # type: ignore[assignment]
    save_servers: dict[str, ServerProfile] | None = None
    save_workspaces: dict[str, WorkspaceProfile] | None = None
    save_schedules: tuple[Path, dict[str, Any]] | None = None
    result: Any = None

    def __post_init__(self) -> None:
        if self.new_secrets is None:
            self.new_secrets = []
        if self.retire_secrets is None:
            self.retire_secrets = []


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
    if not ws.enabled or not ws.allow_oauth_clients:
        return False
    if _PROFILE_RANK.get(client_profile, 0) < _PROFILE_RANK.get(ws.min_profile, 1):
        return False
    if ws.allowed_clients and client_id not in ws.allowed_clients:
        return False
    return ws.permissions_for(client_id).allows(required_perms)


def _backup_once_with_acl(path: Path, suffix: str) -> str:
    bak = path.with_suffix(suffix)
    if not bak.exists():
        shutil.copy2(path, bak)
        get_platform().restrict_path_acl(bak, is_dir=False)
    return str(bak)


def _is_running_in_runtime_ledger(runtime_path: Path, server_name: str) -> bool:
    if not runtime_path.is_file():
        return False
    try:
        raw = json.loads(runtime_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return False
    if not isinstance(raw, dict):
        return False
    entries = raw.get("servers")
    if not isinstance(entries, dict):
        return False
    entry = entries.get(server_name)
    if not isinstance(entry, dict) or not entry.get("running"):
        return False
    pid = entry.get("pid")
    ctime = entry.get("create_time")
    if not isinstance(pid, int) or pid <= 0 or ctime is None:
        return False
    from app.platform import ProcessIdentity

    return bool(get_platform().verify_process_identity(ProcessIdentity(pid=pid, create_time=float(ctime))))


def _assert_server_stopped(
    server_manager: Any,
    server_name: str,
    action: str,
    *,
    server_store: ServerConfigStore | None = None,
) -> None:
    if server_manager is not None:
        try:
            st = server_manager.status_server(server_name, client_id="owner")
            if st.get("running"):
                raise ValueError(f"Stop server {server_name!r} before {action}")
        except ValueError as exc:
            if "Stop server" in str(exc):
                raise
    if server_store is not None:
        runtime_path = server_store.path.with_name("managed_servers.runtime.json")
        if _is_running_in_runtime_ledger(runtime_path, server_name):
            raise ValueError(f"Stop server {server_name!r} before {action}")


def _extract_server_secret_keys(server_store: ServerConfigStore, profile: ServerProfile) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    for ref in profile.env_secret_refs.values():
        try:
            ns, key = server_store.secret_store.parse_ref(ref)
            if ns == SERVER_SECRETS_NS:
                keys.append((ns, key))
        except Exception:  # noqa: BLE001
            pass
    return keys


def _extract_workspace_secret_keys(ws_store: WorkspaceStore, profile: WorkspaceProfile) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    for ref in profile.env_secret_refs.values():
        try:
            ns, key = ws_store.secret_store.parse_ref(ref)
            if ns == WS_SECRETS_NS:
                keys.append((ns, key))
        except Exception:  # noqa: BLE001
            pass
    return keys


def _plan_copied_server_secrets(
    server_store: ServerConfigStore,
    old_profile: ServerProfile,
    new_name: str,
) -> tuple[dict[str, str], list[tuple[str, str, str]], list[tuple[str, str]]]:
    new_refs: dict[str, str] = {}
    to_create: list[tuple[str, str, str]] = []
    old_keys: list[tuple[str, str]] = []
    for env_key, ref in old_profile.env_secret_refs.items():
        val = server_store.secret_store.resolve_ref(ref)
        if val is None:
            raise ValueError(f"Missing secret for {old_profile.name!r} env var {env_key!r}")
        new_secret_key = f"{new_name}__{env_key}"
        new_refs[env_key] = server_store.secret_store.secret_ref(SERVER_SECRETS_NS, new_secret_key)
        to_create.append((SERVER_SECRETS_NS, new_secret_key, val))
        try:
            ns, old_key = server_store.secret_store.parse_ref(ref)
            if ns == SERVER_SECRETS_NS:
                old_keys.append((ns, old_key))
        except Exception:  # noqa: BLE001
            pass
    return new_refs, to_create, old_keys


def _delete_secret_keys(secret_store: Any, pairs: Iterable[tuple[str, str]]) -> None:
    for ns, key in pairs:
        try:
            secret_store.delete_secret(ns, key)
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


def _rewrite_workspace_links_map(
    workspaces: dict[str, WorkspaceProfile], old_name: str, new_name: str
) -> bool:
    changed = False
    for wid, ws in list(workspaces.items()):
        if old_name not in ws.linked_servers:
            continue
        workspaces[wid] = replace(
            ws,
            linked_servers=_dedupe_preserve([new_name if s == old_name else s for s in ws.linked_servers]),
        )
        changed = True
    return changed


def _rename_schedule_entry(entry: Any, old_name: str, new_name: str) -> bool:
    if not isinstance(entry, dict):
        return False
    tname = str(entry.get("tool_name") or "")
    args = entry.get("arguments")
    if (tname == "oauth_managed_server" or tname.startswith("server_")) and isinstance(args, dict):
        if args.get("name") == old_name:
            args["name"] = new_name
            return True
    return False


def _plan_schedule_rename(schedules_path: Path, old_name: str, new_name: str) -> tuple[Path, dict[str, Any]] | None:
    if not schedules_path.is_file():
        return None
    raw = json.loads(schedules_path.read_text(encoding="utf-8-sig"))
    if not isinstance(raw, dict) or not isinstance(raw.get("schedules"), dict):
        return None
    changed = False
    for entry in raw["schedules"].values():
        if _rename_schedule_entry(entry, old_name, new_name):
            changed = True
    return (schedules_path, raw) if changed else None


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
    srv_profile: ServerProfile,
    *,
    client_id: str,
    client_profile: str,
    required: tuple[str, ...],
    workspace_id: str,
) -> list[str]:
    clean_srv = srv_profile.name
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
        if srv_profile.workspace_scoped:
            raise PermissionError(
                f"Server {clean_srv!r} is workspace-scoped with no active linked workspace; "
                "owner must link a workspace or explicitly allow standalone access"
            )
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


def _canonical_path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _assert_no_reparse_target(target: Path, label: str) -> None:
    if is_reparse_or_symlink(target.parent) or is_reparse_or_symlink(target):
        raise ValueError(f"Refusing symlink/reparse {label}: {target}")


def _validate_preimage_content(kind: str, content: Any, raw_path: str) -> str | None:
    if content is None:
        return None
    if not isinstance(content, str):
        raise ValueError(f"Invalid preimage type for {raw_path!r}")
    encoded = content.encode("utf-8")
    if kind == "marker":
        if len(encoded) > _MAX_MARKER_BYTES:
            raise ValueError(f"Oversized marker preimage for {raw_path!r}")
        return content
    if len(encoded) > _MAX_PREIMAGE_FILE_BYTES:
        raise ValueError(f"Oversized JSON preimage for {raw_path!r}")
    try:
        parsed = json.loads(content)
    except ValueError as exc:
        raise ValueError(f"Invalid JSON preimage for {raw_path!r}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"JSON preimage must be an object for {raw_path!r}")
    return content


def _extract_preimage_server_secret_keys(
    server_store: ServerConfigStore,
    srv_preimage: str | None,
) -> set[tuple[str, str]]:
    if not srv_preimage:
        return set()
    parsed = json.loads(srv_preimage)
    raw_servers = parsed.get("servers")
    if not isinstance(raw_servers, dict):
        return set()
    existing_keys: set[tuple[str, str]] = set()
    for raw_prof in raw_servers.values():
        if not isinstance(raw_prof, dict):
            continue
        refs = raw_prof.get("env_secret_refs")
        if not isinstance(refs, dict):
            continue
        for ref in refs.values():
            try:
                ns, key = server_store.secret_store.parse_ref(str(ref))
                existing_keys.add((ns, key))
            except Exception:  # noqa: BLE001
                pass
    return existing_keys


def _capture_preimages(paths: Iterable[Path]) -> dict[str, str | None]:
    snapshots: dict[str, str | None] = {}
    for p in paths:
        _assert_no_reparse_target(p, "config file")
        if p.exists():
            snapshots[str(p)] = p.read_text(encoding="utf-8")
        else:
            snapshots[str(p)] = None
    return snapshots


def _restore_preimages(preimages: Iterable[tuple[Path | str, str | None]] | dict[str, str | None]) -> None:
    items = preimages.items() if isinstance(preimages, dict) else preimages
    for raw_path, content in items:
        target = Path(raw_path)
        _assert_no_reparse_target(target, "tx recovery target")
        if content is None:
            if target.exists():
                target.unlink(missing_ok=True)
            continue
        current = target.read_text(encoding="utf-8") if target.exists() else None
        if current != content:
            atomic_write_text(target, content, encoding="utf-8", restrict_acl=True)


class WorkspaceServerCoordinator:
    """Single-source coordinator linking WorkspaceProfile.linked_servers to ServerConfigStore."""

    def __init__(
        self,
        workspace_store: WorkspaceStore,
        server_store: ServerConfigStore,
        *,
        automation_dir: Path | None = None,
    ) -> None:
        self.workspace_store = workspace_store
        self.server_store = server_store
        self.automation_dir = Path(automation_dir) if automation_dir is not None else None
        self._tx_path = self.workspace_store.path.parent / _TX_FILENAME

    def _schedules_paths(self) -> tuple[Path, Path] | None:
        if self.automation_dir is None:
            return None
        return (self.automation_dir / _SCHEDULES_FILENAME, self.automation_dir / _AUTOMATION_LOCK_FILENAME)

    def _enter_coordinator_locks(self, stack: ExitStack, *, lock_automation: bool = False) -> bool:
        stack.enter_context(self.workspace_store.lock())
        stack.enter_context(self.server_store.lock())
        sched = self._schedules_paths()
        if sched is not None and (lock_automation or self._tx_path.exists()):
            stack.enter_context(cross_process_lock(sched[1]))
            return True
        return False

    def _allowed_tx_targets(self) -> dict[str, tuple[Path, Literal["json", "marker"], bool]]:
        targets: list[tuple[Path, Literal["json", "marker"], bool]] = [
            (self.workspace_store.path, "json", False),
            (self.workspace_store._init_marker, "marker", False),
            (self.server_store.path, "json", False),
            (self.server_store._init_marker, "marker", False),
        ]
        sched = self._schedules_paths()
        if sched is not None:
            targets.append((sched[0], "json", True))
        return {_canonical_path_key(p): (p, kind, is_sched) for p, kind, is_sched in targets}

    def _validate_journal_files(
        self,
        files_raw: Any,
    ) -> tuple[list[tuple[Path, str | None]], bool, bool, str | None]:
        if not isinstance(files_raw, dict):
            raise ValueError(f"Invalid files map in coordinator tx journal: {self._tx_path}")
        allowed = self._allowed_tx_targets()
        seen: set[str] = set()
        validated: list[tuple[Path, str | None]] = []
        needs_automation = False
        has_srv_entry = False
        srv_preimage: str | None = None
        srv_canon = _canonical_path_key(self.server_store.path)
        for raw_path, content in files_raw.items():
            if not isinstance(raw_path, str):
                raise ValueError(f"Invalid path key in coordinator tx journal: {raw_path!r}")
            canon = _canonical_path_key(Path(raw_path))
            spec = allowed.get(canon)
            if spec is None or canon in seen:
                raise ValueError(f"Disallowed tx journal target path: {raw_path!r}")
            seen.add(canon)
            actual_path, kind, is_sched = spec
            _assert_no_reparse_target(actual_path, "tx target")
            clean_content = _validate_preimage_content(kind, content, raw_path)
            validated.append((actual_path, clean_content))
            if is_sched:
                needs_automation = True
            if canon == srv_canon:
                has_srv_entry = True
                srv_preimage = clean_content
        return validated, needs_automation, has_srv_entry, srv_preimage

    def _validate_journal_secrets(
        self,
        created_raw: Any,
        *,
        has_srv_entry: bool,
        srv_preimage: str | None,
    ) -> list[tuple[str, str]]:
        if not isinstance(created_raw, list):
            raise ValueError(f"Invalid created_secrets list in coordinator tx journal: {self._tx_path}")
        if not created_raw:
            return []
        if not has_srv_entry:
            raise ValueError("Coordinator tx journal with created_secrets must protect managed_servers.json")
        existing_keys = _extract_preimage_server_secret_keys(self.server_store, srv_preimage)
        out: list[tuple[str, str]] = []
        for item in created_raw:
            if not isinstance(item, list) or len(item) != 2:
                raise ValueError(f"Invalid created_secrets item in tx journal: {item!r}")
            ns, key = item[0], item[1]
            if not isinstance(ns, str) or not isinstance(key, str) or ns != SERVER_SECRETS_NS:
                raise ValueError(f"Disallowed secret namespace in tx journal: {item!r}")
            clean_key = SecretStore._validate_key(key)
            if "__" not in clean_key:
                raise ValueError(f"Malformed server secret key in tx journal: {clean_key!r}")
            validate_server_name(clean_key.split("__", 1)[0])
            if (ns, clean_key) in existing_keys:
                raise ValueError(f"Refusing to delete pre-existing server secret during tx recovery: {clean_key!r}")
            out.append((ns, clean_key))
        return out

    def _read_and_validate_tx_journal(self) -> tuple[list[tuple[Path, str | None]], list[tuple[str, str]], bool]:
        _assert_no_reparse_target(self._tx_path, "tx journal")
        try:
            st = self._tx_path.lstat()
        except OSError as exc:
            raise ValueError(f"Unreadable coordinator tx journal: {self._tx_path}") from exc
        if st.st_size <= 0 or st.st_size > _MAX_TX_JOURNAL_BYTES:
            raise ValueError(f"Invalid coordinator tx journal size ({st.st_size} bytes): {self._tx_path}")
        try:
            journal = json.loads(self._tx_path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"Corrupt pending coordinator transaction journal: {self._tx_path}") from exc
        if not isinstance(journal, dict) or set(journal.keys()) != _TX_TOP_KEYS:
            raise ValueError(f"Invalid pending coordinator transaction journal: {self._tx_path}")
        ver = journal.get("schema_version")
        if type(ver) is not int or ver != 1:
            raise ValueError(f"Unsupported coordinator tx journal schema_version: {ver!r}")
        validated_files, needs_auto, has_srv, srv_pre = self._validate_journal_files(journal.get("files"))
        validated_secrets = self._validate_journal_secrets(
            journal.get("created_secrets"),
            has_srv_entry=has_srv,
            srv_preimage=srv_pre,
        )
        return validated_files, validated_secrets, needs_auto

    def _recover_pending_tx_unlocked(self, *, automation_locked: bool = False) -> None:
        if not os.path.lexists(self._tx_path):
            return
        validated_files, validated_secrets, needs_auto = self._read_and_validate_tx_journal()
        with ExitStack() as stack:
            if needs_auto and not automation_locked:
                sched = self._schedules_paths()
                if sched is None:
                    raise ValueError("Coordinator tx journal requires automation_dir for schedules.json recovery")
                stack.enter_context(cross_process_lock(sched[1]))
            _restore_preimages(validated_files)
            _delete_secret_keys(self.server_store.secret_store, validated_secrets)
            self._tx_path.unlink(missing_ok=True)

    def _apply_tx_writes(self, plan: _TxMutationPlan, written_secrets: list[tuple[str, str]]) -> None:
        for ns, key, val in plan.new_secrets:
            store = self.server_store.secret_store if ns == SERVER_SECRETS_NS else self.workspace_store.secret_store
            store.set_secret(ns, key, val)
            written_secrets.append((ns, key))
        if plan.save_servers is not None:
            self.server_store.save_profiles(plan.save_servers)
        if plan.save_workspaces is not None:
            self.workspace_store.save_workspaces(plan.save_workspaces)
        if plan.save_schedules is not None:
            atomic_write_json(plan.save_schedules[0], plan.save_schedules[1], indent=2, restrict_acl=True)

    def _retire_tx_secrets(self, retire_secrets: list[tuple[str, str]]) -> None:
        for ns, key in retire_secrets:
            store = self.server_store.secret_store if ns == SERVER_SECRETS_NS else self.workspace_store.secret_store
            _delete_secret_keys(store, [(ns, key)])

    def _run_tx(
        self,
        plan_fn: Callable[[], _TxMutationPlan],
        *,
        lock_automation: bool = False,
    ) -> Any:
        with ExitStack() as stack:
            auto_locked = self._enter_coordinator_locks(stack, lock_automation=lock_automation)

            self._recover_pending_tx_unlocked(automation_locked=auto_locked)
            plan = plan_fn()
            watch_paths = list(dict.fromkeys([
                *plan.files_to_watch,
                self.workspace_store._init_marker,
                self.server_store._init_marker,
            ]))
            preimages = _capture_preimages(watch_paths)
            written_secrets: list[tuple[str, str]] = []
            atomic_write_json(
                self._tx_path,
                {
                    "schema_version": 1,
                    "files": preimages,
                    "created_secrets": [[ns, key] for ns, key, _ in plan.new_secrets],
                },
                indent=2,
                restrict_acl=True,
            )
            try:
                self._apply_tx_writes(plan, written_secrets)
            except BaseException:
                _restore_preimages(preimages)
                _delete_secret_keys(self.server_store.secret_store, written_secrets)
                _delete_secret_keys(self.workspace_store.secret_store, written_secrets)
                self._tx_path.unlink(missing_ok=True)
                raise

            # Durable commit point reached: remove journal before deleting retired secrets.
            self._tx_path.unlink(missing_ok=True)
            self._retire_tx_secrets(plan.retire_secrets)
            return plan.result

    def _load_for_migration(self) -> tuple[dict[str, ServerProfile], bool, dict[str, WorkspaceProfile], bool]:
        migrated_servers = False
        if self.server_store.path.exists() and self.server_store.detect_schema_version() < SRV_SCHEMA_VERSION:
            _backup_once_with_acl(self.server_store.path, ".json.v1.bak")
            migrated_servers = True
        servers = self.server_store.load_profiles(strict=True)

        migrated_workspaces = False
        if self.workspace_store.path.exists() and self.workspace_store.detect_schema_version() < WS_SCHEMA_VERSION:
            _backup_once_with_acl(self.workspace_store.path, ".json.v1.bak")
            migrated_workspaces = True
        workspaces = self.workspace_store.load_workspaces()
        return servers, migrated_servers, workspaces, migrated_workspaces

    def ensure_migrated(self) -> dict[str, Any]:
        """Idempotently normalize legacy v1.0.2 schemas and set workspace_scoped on linked servers."""

        def _plan() -> _TxMutationPlan:
            servers, migrated_servers, workspaces, migrated_workspaces = self._load_for_migration()
            linked_names = {srv for ws in workspaces.values() for srv in ws.linked_servers}
            scoped_changed = self._sync_scope_flags(
                servers, workspaces, linked_names, allow_unscoped_access=False
            )
            summary = {
                "migrated_servers": migrated_servers,
                "migrated_workspaces": migrated_workspaces,
                "workspaces": len(workspaces),
                "servers": len(servers),
            }
            return _TxMutationPlan(
                files_to_watch=(self.server_store.path, self.workspace_store.path),
                save_servers=servers if (migrated_servers or scoped_changed) else None,
                save_workspaces=workspaces if migrated_workspaces else None,
                result=summary,
            )

        return self._run_tx(_plan)

    def partition_servers(self) -> WorkspaceServersSnapshot:
        """Return consistent workspace-linked and unlinked ServerProfile partitions."""
        with ExitStack() as stack:
            auto_locked = self._enter_coordinator_locks(stack)
            self._recover_pending_tx_unlocked(automation_locked=auto_locked)
            workspaces = self.workspace_store.load_workspaces()
            servers = self.server_store.load_profiles(strict=True)

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
        """Link an existing ServerProfile to a WorkspaceProfile and mark it workspace-scoped."""
        clean_wid = validate_workspace_id(workspace_id)
        clean_srv = validate_server_name(server_name)

        def _plan() -> _TxMutationPlan:
            workspaces = self.workspace_store.load_workspaces()
            ws = workspaces.get(clean_wid)
            if ws is None:
                raise KeyError(f"Unknown workspace: {clean_wid!r}")
            servers = self.server_store.load_profiles(strict=True)
            srv = servers.get(clean_srv)
            if srv is None:
                raise ValueError(f"Unknown server profile: {clean_srv!r}")

            save_srv = None
            if not srv.workspace_scoped:
                servers[clean_srv] = replace(srv, workspace_scoped=True)
                save_srv = servers

            if clean_srv in ws.linked_servers:
                return _TxMutationPlan(
                    files_to_watch=(self.server_store.path, self.workspace_store.path),
                    save_servers=save_srv,
                    result=ws,
                )
            updated = replace(ws, linked_servers=_dedupe_preserve([*ws.linked_servers, clean_srv]))
            workspaces[clean_wid] = updated
            return _TxMutationPlan(
                files_to_watch=(self.server_store.path, self.workspace_store.path),
                save_servers=save_srv,
                save_workspaces=workspaces,
                result=updated,
            )

        return self._run_tx(_plan)

    def unlink_server(
        self,
        workspace_id: str,
        server_name: str,
        *,
        allow_unscoped_access: bool = False,
    ) -> WorkspaceProfile:
        """Unlink a server without implicitly widening effective client permissions."""
        clean_wid = validate_workspace_id(workspace_id)
        clean_srv = validate_server_name(server_name)

        def _plan() -> _TxMutationPlan:
            workspaces = self.workspace_store.load_workspaces()
            ws = workspaces.get(clean_wid)
            if ws is None:
                raise KeyError(f"Unknown workspace: {clean_wid!r}")
            new_links = tuple(s for s in ws.linked_servers if s != clean_srv)
            save_ws = None
            result_ws = ws
            if new_links != ws.linked_servers:
                result_ws = replace(ws, linked_servers=new_links)
                workspaces[clean_wid] = result_ws
                save_ws = workspaces

            save_srv = None
            if allow_unscoped_access:
                servers = self.server_store.load_profiles(strict=True)
                srv = servers.get(clean_srv)
                still_linked = any(clean_srv in other.linked_servers for other in workspaces.values())
                if srv is not None and srv.workspace_scoped and not still_linked:
                    servers[clean_srv] = replace(srv, workspace_scoped=False)
                    save_srv = servers

            return _TxMutationPlan(
                files_to_watch=(self.server_store.path, self.workspace_store.path),
                save_servers=save_srv,
                save_workspaces=save_ws,
                result=result_ws,
            )

        return self._run_tx(_plan)

    @staticmethod
    def _sync_scope_flags(
        servers: dict[str, ServerProfile],
        workspaces: dict[str, WorkspaceProfile],
        candidates: Iterable[str],
        *,
        allow_unscoped_access: bool,
    ) -> bool:
        changed = False
        for sname in candidates:
            srv = servers.get(sname)
            if srv is None:
                continue
            still_linked = any(sname in other.linked_servers for other in workspaces.values())
            if allow_unscoped_access and not still_linked and srv.workspace_scoped:
                servers[sname] = replace(srv, workspace_scoped=False)
                changed = True
            elif not allow_unscoped_access and not srv.workspace_scoped:
                servers[sname] = replace(srv, workspace_scoped=True)
                changed = True
        return changed

    def set_workspace_servers(
        self,
        workspace_id: str,
        server_names: tuple[str, ...] | list[str],
        *,
        allow_unscoped_access: bool = False,
    ) -> WorkspaceProfile:
        """Replace linked_servers on one workspace without implicitly widening unlinked servers."""
        clean_wid = validate_workspace_id(workspace_id)
        normalized = _dedupe_preserve([validate_server_name(s) for s in server_names])

        def _plan() -> _TxMutationPlan:
            workspaces = self.workspace_store.load_workspaces()
            ws = workspaces.get(clean_wid)
            if ws is None:
                raise KeyError(f"Unknown workspace: {clean_wid!r}")
            servers = self.server_store.load_profiles(strict=True)
            for sname in normalized:
                if sname not in servers and sname not in ws.linked_servers:
                    raise ValueError(f"Unknown server profile: {sname!r}")

            removed = [s for s in ws.linked_servers if s not in normalized]
            updated = replace(ws, linked_servers=normalized)
            workspaces[clean_wid] = updated
            srv_changed = self._sync_scope_flags(
                servers, workspaces, normalized, allow_unscoped_access=False
            )
            if allow_unscoped_access:
                srv_changed = self._sync_scope_flags(
                    servers, workspaces, removed, allow_unscoped_access=True
                ) or srv_changed

            return _TxMutationPlan(
                files_to_watch=(self.server_store.path, self.workspace_store.path),
                save_servers=servers if srv_changed else None,
                save_workspaces=workspaces,
                result=updated,
            )

        return self._run_tx(_plan)

    def set_server_workspace_scoped(self, server_name: str, workspace_scoped: bool) -> ServerProfile:
        """Explicit owner policy action controlling whether an unlinked server rejects client access."""
        clean_srv = validate_server_name(server_name)

        def _plan() -> _TxMutationPlan:
            servers = self.server_store.load_profiles(strict=True)
            srv = servers.get(clean_srv)
            if srv is None:
                raise KeyError(f"Unknown server profile: {clean_srv!r}")
            updated = replace(srv, workspace_scoped=bool(workspace_scoped))
            servers[clean_srv] = updated
            return _TxMutationPlan(
                files_to_watch=(self.server_store.path,),
                save_servers=servers if updated != srv else None,
                result=updated,
            )

        return self._run_tx(_plan)

    def delete_workspace_preserving_servers(
        self,
        workspace_id: str,
        *,
        delete_secrets: bool = True,
        allow_unscoped_access: bool = False,
    ) -> bool:
        """Delete workspace without stopping servers or implicitly widening server permissions."""
        clean_wid = validate_workspace_id(workspace_id)

        def _plan() -> _TxMutationPlan:
            workspaces = self.workspace_store.load_workspaces()
            removed = workspaces.pop(clean_wid, None)
            if removed is None:
                return _TxMutationPlan(files_to_watch=(self.workspace_store.path,), result=False)

            servers = self.server_store.load_profiles(strict=True)
            srv_changed = self._sync_scope_flags(
                servers,
                workspaces,
                removed.linked_servers,
                allow_unscoped_access=allow_unscoped_access,
            )
            retire = _extract_workspace_secret_keys(self.workspace_store, removed) if delete_secrets else []
            return _TxMutationPlan(
                files_to_watch=(self.server_store.path, self.workspace_store.path),
                retire_secrets=retire,
                save_servers=servers if srv_changed else None,
                save_workspaces=workspaces,
                result=True,
            )

        return bool(self._run_tx(_plan))

    def delete_server_and_unlink(
        self,
        server_name: str,
        *,
        server_manager: Any = None,
        delete_secrets: bool = True,
    ) -> bool:
        """Atomically delete a stopped, undepended server profile and remove workspace links."""
        clean_srv = validate_server_name(server_name)
        _assert_server_stopped(server_manager, clean_srv, "deleting", server_store=self.server_store)

        def _plan() -> _TxMutationPlan:
            _assert_server_stopped(None, clean_srv, "deleting", server_store=self.server_store)
            profiles = self.server_store.load_profiles(strict=True)
            removed = profiles.pop(clean_srv, None)
            if removed is None:
                return _TxMutationPlan(files_to_watch=(self.server_store.path,), result=False)

            dependents = [other.name for other in profiles.values() if clean_srv in other.depends_on]
            if dependents:
                raise ValueError(
                    f"Cannot delete {clean_srv!r}: depended on by {', '.join(sorted(dependents))}"
                )

            workspaces = self.workspace_store.load_workspaces()
            ws_changed = False
            for wid, ws in list(workspaces.items()):
                if clean_srv in ws.linked_servers:
                    workspaces[wid] = replace(
                        ws,
                        linked_servers=tuple(s for s in ws.linked_servers if s != clean_srv),
                    )
                    ws_changed = True

            retire = _extract_server_secret_keys(self.server_store, removed) if delete_secrets else []
            return _TxMutationPlan(
                files_to_watch=(self.server_store.path, self.workspace_store.path),
                retire_secrets=retire,
                save_servers=profiles,
                save_workspaces=workspaces if ws_changed else None,
                result=True,
            )

        return bool(self._run_tx(_plan))

    def rename_server(
        self,
        old_name: str,
        new_name: str,
        *,
        server_manager: Any = None,
    ) -> ServerProfile:
        """Atomically rename server ID, secrets, depends_on, workspace links, and schedules."""
        clean_old = validate_server_name(old_name)
        clean_new = validate_server_name(new_name)
        if clean_old == clean_new:
            raise ValueError("New server name must differ from current name")
        _assert_server_stopped(server_manager, clean_old, "renaming", server_store=self.server_store)

        def _plan() -> _TxMutationPlan:
            _assert_server_stopped(None, clean_old, "renaming", server_store=self.server_store)
            profiles = self.server_store.load_profiles(strict=True)
            old_prof = profiles.get(clean_old)
            if old_prof is None:
                raise ValueError(f"Unknown server profile: {clean_old!r}")
            if clean_new in profiles:
                raise ValueError(f"Server '{clean_new}' already exists")

            new_refs, to_create, old_keys = _plan_copied_server_secrets(
                self.server_store, old_prof, clean_new
            )
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

            workspaces = self.workspace_store.load_workspaces()
            ws_changed = _rewrite_workspace_links_map(workspaces, clean_old, clean_new)

            sched_paths = self._schedules_paths()
            save_sched = _plan_schedule_rename(sched_paths[0], clean_old, clean_new) if sched_paths else None
            watch: list[Path] = [self.server_store.path, self.workspace_store.path]
            if save_sched is not None:
                watch.append(save_sched[0])

            return _TxMutationPlan(
                files_to_watch=tuple(watch),
                new_secrets=to_create,
                retire_secrets=old_keys,
                save_servers=profiles,
                save_workspaces=workspaces if ws_changed else None,
                save_schedules=save_sched,
                result=renamed,
            )

        return self._run_tx(_plan, lock_automation=True)

    def authorize_server_operation(
        self,
        server_name: str,
        *,
        client_id: str | None,
        client_profile: str,
        mode: Literal["read", "control"] = "read",
        workspace_id: str = "",
    ) -> list[str]:
        """Fail-closed check intersecting caller permissions across workspaces and server scoping."""
        if mode not in _VALID_SERVER_MODES:
            raise PermissionError(f"Invalid server access mode: {mode!r}")
        clean_srv = validate_server_name(server_name)
        try:
            with ExitStack() as stack:
                auto_locked = self._enter_coordinator_locks(stack)
                self._recover_pending_tx_unlocked(automation_locked=auto_locked)
                workspaces = self.workspace_store.load_workspaces()
                servers = self.server_store.load_profiles(strict=True)
        except Exception as exc:  # noqa: BLE001
            raise PermissionError(f"Workspace authorization store unavailable: {type(exc).__name__}") from exc

        linked_wids = [wid for wid in sorted(workspaces) if clean_srv in workspaces[wid].linked_servers]
        if _is_owner(client_id):
            return _authorize_owner_server_op(workspaces, linked_wids, clean_srv, workspace_id)

        srv_profile = servers.get(clean_srv)
        if srv_profile is None:
            raise KeyError(f"Unknown server profile: {clean_srv!r}")

        assert isinstance(client_id, str) and client_id
        required = ("read",) if mode == "read" else ("read", "execute")
        return _authorize_client_server_op(
            workspaces,
            linked_wids,
            srv_profile,
            client_id=client_id,
            client_profile=client_profile,
            required=required,
            workspace_id=workspace_id,
        )

    @staticmethod
    def _normalize_new_wizard_server(srv: ServerProfile) -> ServerProfile:
        normalized = replace(
            srv,
            workspace_scoped=True,
            autostart=False,
            expose_externally=False,
            env_secret_refs={},
            min_profile="full",
        )
        normalized.validate()
        return normalized

    @staticmethod
    def _inspect_root_relations(
        canon_root: Path,
        root_ident: tuple[int, int] | None,
        workspaces: dict[str, WorkspaceProfile],
    ) -> tuple[list[str], list[str]]:
        conflicts: list[str] = []
        nested: list[str] = []
        canon_norm = os.path.normcase(str(canon_root))
        for wid, existing in sorted(workspaces.items()):
            try:
                ex_canon = canonical_workspace_root(existing.root_path)
            except Exception:  # noqa: BLE001
                continue
            ex_norm = os.path.normcase(str(ex_canon))
            ex_ident = compute_root_identity(ex_canon)
            same_ident = root_ident is not None and ex_ident is not None and root_ident == ex_ident
            if canon_norm == ex_norm or same_ident:
                conflicts.append(f"Directory is already registered under workspace '{wid}'")
            elif canon_root.is_relative_to(ex_canon) or ex_canon.is_relative_to(canon_root):
                nested.append(wid)
        return conflicts, nested

    @staticmethod
    def _inspect_server_conflicts(
        new_servers: list[ServerProfile],
        link_existing_servers: list[str],
        servers: dict[str, ServerProfile],
    ) -> list[str]:
        conflicts: list[str] = []
        existing_srv_cf = {sname.casefold(): sname for sname in servers}
        seen_new: set[str] = set()
        for srv in new_servers:
            low = srv.name.casefold()
            if low in seen_new:
                conflicts.append(f"Duplicate new server name '{srv.name}'")
            seen_new.add(low)
            if low in existing_srv_cf:
                conflicts.append(f"Server '{srv.name}' conflicts with existing '{existing_srv_cf[low]}'")
        for sname in link_existing_servers:
            if sname not in servers:
                conflicts.append(f"Existing server '{sname}' does not exist")
        return conflicts

    @staticmethod
    def _collect_addition_warnings(profile: WorkspaceProfile, nested: list[str]) -> list[str]:
        warnings: list[str] = []
        if profile.allow_oauth_clients and not profile.allowed_clients:
            warnings.append("All approved OAuth clients meeting min_profile will be allowed")
        if profile.permissions.execute:
            warnings.append("Named workspace command execution is enabled")
        if nested:
            warnings.append(f"Nested relationship with existing workspace(s): {', '.join(nested)}")
        return warnings

    @staticmethod
    def _inspect_addition_conflicts(
        profile: WorkspaceProfile,
        new_servers: list[ServerProfile],
        link_existing_servers: list[str],
        workspaces: dict[str, WorkspaceProfile],
        servers: dict[str, ServerProfile],
    ) -> tuple[Path, tuple[int, int] | None, list[str], list[str], list[str]]:
        profile.validate()
        canon_root = canonical_workspace_root(profile.root_path)
        root_ident = compute_root_identity(canon_root)

        conflicts: list[str] = []
        existing_wid_cf = {wid.casefold(): wid for wid in workspaces}
        matched = existing_wid_cf.get(profile.workspace_id.casefold())
        if matched is not None:
            conflicts.append(f"Workspace ID '{profile.workspace_id}' conflicts with existing '{matched}'")

        root_conflicts, nested = WorkspaceServerCoordinator._inspect_root_relations(
            canon_root, root_ident, workspaces
        )
        conflicts.extend(root_conflicts)
        conflicts.extend(
            WorkspaceServerCoordinator._inspect_server_conflicts(new_servers, link_existing_servers, servers)
        )
        warnings = WorkspaceServerCoordinator._collect_addition_warnings(profile, nested)
        return canon_root, root_ident, conflicts, nested, warnings

    @staticmethod
    def _effective_permissions_summary(profile: WorkspaceProfile) -> dict[str, Any]:
        if not profile.allow_oauth_clients:
            oauth_mode = "deny_all"
        elif profile.allowed_clients:
            oauth_mode = "allowlist_clients"
        else:
            oauth_mode = "all_approved_clients"
        return {
            **profile.permissions.to_dict(),
            "allow_oauth_clients": bool(profile.allow_oauth_clients),
            "oauth_mode": oauth_mode,
            "allowed_clients": list(profile.allowed_clients),
            "min_profile": profile.min_profile,
            "trust_git_hooks": bool(profile.trust_git_hooks),
        }

    def prepare_addition_preview(
        self,
        profile: WorkspaceProfile,
        *,
        new_servers: Iterable[ServerProfile] = (),
        link_existing_servers: Iterable[str] = (),
        expected_manifest_digests: Mapping[str, str] | None = None,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> WizardAdditionPreview:
        """Build a consistent non-mutating preview + state fingerprint for the Workspace Wizard."""
        normalized_new = [self._normalize_new_wizard_server(s) for s in new_servers]
        normalized_links = list(_dedupe_preserve([validate_server_name(s) for s in link_existing_servers]))

        with ExitStack() as stack:
            auto_locked = self._enter_coordinator_locks(stack)
            self._recover_pending_tx_unlocked(automation_locked=auto_locked)
            workspaces = self.workspace_store.load_workspaces()
            servers = self.server_store.load_profiles(strict=True)

        canon_root, root_ident, conflicts, nested, warnings = self._inspect_addition_conflicts(
            profile, normalized_new, normalized_links, workspaces, servers
        )
        if expected_root_identity is not None and root_ident != expected_root_identity:
            raise WizardStalePlanError("Workspace directory identity changed on disk since analysis")
        digests = dict(expected_manifest_digests if expected_manifest_digests is not None else profile.manifest_digests)
        if digests:
            verify_manifest_digests(canon_root, digests)

        combined_links = _dedupe_preserve([*profile.linked_servers, *(s.name for s in normalized_new), *normalized_links])
        preview_profile = replace(profile, root_path=str(canon_root), linked_servers=combined_links, manifest_digests=digests)
        snapshot = WizardPlanSnapshot(
            state_fingerprint=compute_registry_fingerprint(workspaces, servers),
            root_path=str(canon_root),
            root_identity=root_ident,
            manifest_digests=digests,
            existing_workspace_ids=tuple(sorted(workspaces)),
            existing_server_names=tuple(sorted(servers)),
        )
        return WizardAdditionPreview(
            profile=preview_profile,
            new_servers=tuple(normalized_new),
            link_existing_servers=tuple(normalized_links),
            conflicts=tuple(conflicts),
            nested_workspaces=tuple(nested),
            warnings=tuple(warnings),
            effective_permissions=self._effective_permissions_summary(preview_profile),
            snapshot=snapshot,
        )

    @staticmethod
    def _verify_commit_preconditions(
        profile: WorkspaceProfile,
        normalized_new: list[ServerProfile],
        normalized_links: list[str],
        workspaces: dict[str, WorkspaceProfile],
        servers: dict[str, ServerProfile],
        *,
        expected_state_fingerprint: str,
        expected_root_identity: tuple[int, int] | None,
        expected_manifest_digests: Mapping[str, str] | None,
        acknowledge_nested: bool,
        ack_nested_set: set[str],
    ) -> tuple[Path, dict[str, str]]:
        if compute_registry_fingerprint(workspaces, servers) != expected_state_fingerprint:
            raise WizardStalePlanError(
                "Workspace or server registry changed since preview; refresh preview before committing"
            )
        canon_root, root_ident, conflicts, nested, _warnings = WorkspaceServerCoordinator._inspect_addition_conflicts(
            profile, normalized_new, normalized_links, workspaces, servers
        )
        if expected_root_identity is not None and root_ident != expected_root_identity:
            raise WizardStalePlanError("Workspace root directory changed on disk since preview")
        digests = dict(expected_manifest_digests if expected_manifest_digests is not None else profile.manifest_digests)
        if digests:
            verify_manifest_digests(canon_root, digests)
        if conflicts:
            raise WizardConflictError("; ".join(conflicts))
        if nested and (not acknowledge_nested or (ack_nested_set and ack_nested_set != set(nested))):
            raise WizardConflictError(
                f"Nested workspace relationship detected ({', '.join(nested)}); explicit acknowledgement required"
            )
        return canon_root, digests

    def commit_workspace_addition(
        self,
        profile: WorkspaceProfile,
        *,
        new_servers: Iterable[ServerProfile] = (),
        link_existing_servers: Iterable[str] = (),
        expected_state_fingerprint: str,
        expected_root_identity: tuple[int, int] | None = None,
        expected_manifest_digests: Mapping[str, str] | None = None,
        acknowledge_nested: bool = False,
        expected_nested_ids: Iterable[str] = (),
    ) -> dict[str, Any]:
        """Atomically commit a wizard workspace, new scoped servers, and explicit links without autostart."""
        normalized_new = [self._normalize_new_wizard_server(s) for s in new_servers]
        normalized_links = list(_dedupe_preserve([validate_server_name(s) for s in link_existing_servers]))
        ack_nested_set = {str(x).strip() for x in expected_nested_ids if str(x).strip()}

        def _plan() -> _TxMutationPlan:
            workspaces = self.workspace_store.load_workspaces()
            servers = self.server_store.load_profiles(strict=True)
            canon_root, digests = self._verify_commit_preconditions(
                profile,
                normalized_new,
                normalized_links,
                workspaces,
                servers,
                expected_state_fingerprint=expected_state_fingerprint,
                expected_root_identity=expected_root_identity,
                expected_manifest_digests=expected_manifest_digests,
                acknowledge_nested=acknowledge_nested,
                ack_nested_set=ack_nested_set,
            )

            srv_changed = False
            for srv in normalized_new:
                servers[srv.name] = srv
                srv_changed = True
            for sname in normalized_links:
                existing_srv = servers[sname]
                if not existing_srv.workspace_scoped:
                    servers[sname] = replace(existing_srv, workspace_scoped=True)
                    srv_changed = True

            combined_links = _dedupe_preserve(
                [*profile.linked_servers, *(s.name for s in normalized_new), *normalized_links]
            )
            final_ws = replace(
                profile,
                root_path=str(canon_root),
                linked_servers=combined_links,
                manifest_digests=digests,
            )
            final_ws.validate()
            workspaces[final_ws.workspace_id] = final_ws

            return _TxMutationPlan(
                files_to_watch=(self.server_store.path, self.workspace_store.path),
                save_servers=servers if srv_changed else None,
                save_workspaces=workspaces,
                result={
                    "workspace": final_ws,
                    "created_servers": [s.name for s in normalized_new],
                    "linked_servers": list(combined_links),
                },
            )

        return self._run_tx(_plan)
