"""Unit tests for N03: lossless v1.0.2 migration, workspace-server links, concurrency, and permission matrix."""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp.shared.auth import OAuthClientInformationFull

from app.config import Settings
from app.core.secret_store import SecretStore
from app.updater.detector import detect_install_environment
from app.updater.helper import recover_interrupted_update_on_boot
from app.updater.models import UpdateBlockReason, UpdateState
from app.updater.trust import (
    PRODUCTION_PUBLISHER_THUMBPRINTS,
    PRODUCTION_TRUST_ROOTS,
    TrustPolicy,
)
from backend.oauth_store import OAuthStore
from backend.process_runner import ProcessRunner
from backend.servers.manager import ServerManager
from backend.servers.models import ServerProfile
from backend.servers.store import ServerConfigStore
from backend.workspaces.history import WorkspaceHistory
from backend.workspaces.models import WorkspacePermissions, WorkspaceProfile
from backend.workspaces.server_links import WorkspaceServerCoordinator
from backend.workspaces.store import WorkspaceStore


def _make_server(
    name: str,
    cwd: str,
    *,
    lifecycle: str = "controlled",
    min_profile: str = "allowlist",
    allowed_clients: tuple[str, ...] = (),
    depends_on: tuple[str, ...] = (),
    enabled: bool = True,
    env: dict[str, str] | None = None,
    env_secret_refs: dict[str, str] | None = None,
) -> ServerProfile:
    return ServerProfile(
        name=name,
        display_name=f"Display {name}",
        argv=(sys.executable, "-c", "import time; time.sleep(30)"),
        cwd=cwd,
        env=env or {},
        env_secret_refs=env_secret_refs or {},
        lifecycle=lifecycle,
        host="127.0.0.1",
        port=None,
        depends_on=depends_on,
        min_profile=min_profile,
        allowed_clients=allowed_clients,
        enabled=enabled,
    )


class N03WorkspaceServersMigrationAndPermissionsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.secrets_dir = self.root / "secrets"
        self.secret_store = SecretStore(self.secrets_dir)
        self.ws_root_alpha = self.root / "projects" / "alpha"
        self.ws_root_beta = self.root / "projects" / "beta"
        self.ws_root_nested = self.ws_root_alpha / "nested_app"
        self.ws_root_alpha.mkdir(parents=True)
        self.ws_root_beta.mkdir(parents=True)
        self.ws_root_nested.mkdir(parents=True)

        self.ws_store = WorkspaceStore(self.root / "workspaces" / "workspaces.json", secret_store=self.secret_store)
        self.srv_store = ServerConfigStore(self.root / "servers" / "managed_servers.json", secret_store=self.secret_store)
        self.ws_history = WorkspaceHistory(self.root / "workspaces" / "history")
        self.coordinator = WorkspaceServerCoordinator(self.ws_store, self.srv_store)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_lossless_v102_migration_preserves_data_and_never_auto_links(self) -> None:
        ws_secret_ref = self.ws_store.set_env_secret("ws_alpha", "WS_KEY", "ws-secret-value-alpha")
        srv_secret_ref = self.srv_store.set_env_secret("api_alpha", "SRV_KEY", "srv-secret-value-alpha")

        # Legacy v1.0.2 workspaces.json (schema_version=1, duplicate/stale refs, linked & unlinked)
        ws_payload = {
            "schema_version": 1,
            "workspaces": {
                "ws_alpha": {
                    "workspace_id": "ws_alpha",
                    "name": "Alpha Project",
                    "root_path": str(self.ws_root_alpha),
                    "language": "python",
                    "commands": {"test": "python -m unittest"},
                    "env": {"APP_MODE": "dev"},
                    "env_secret_refs": {"WS_KEY": ws_secret_ref},
                    "linked_servers": ["api_alpha", "shared_redis", "api_alpha", "ghost_srv"],
                    "linked_tasks": ["task-001", "task-001"],
                    "linked_extensions": ["ext.alpha"],
                    "permissions": {"read": True, "write": True, "delete": False, "execute": True, "git": True},
                    "client_permissions": {
                        "client-ro": {"read": True, "write": False, "delete": False, "execute": False, "git": False},
                    },
                    "allowed_clients": ["client-rw", "client-ro"],
                    "min_profile": "allowlist",
                    "enabled": True,
                },
                "ws_beta": {
                    "workspace_id": "ws_beta",
                    "name": "Beta Project",
                    "root_path": str(self.ws_root_beta),
                    "linked_servers": ["shared_redis"],
                    "permissions": {"read": True, "write": False, "delete": False, "execute": True, "git": False},
                    "allowed_clients": ["client-beta"],
                    "min_profile": "full",
                    "enabled": True,
                },
                "ws_disabled": {
                    "workspace_id": "ws_disabled",
                    "name": "Disabled Project",
                    "root_path": str(self.ws_root_nested),
                    "linked_servers": [],
                    "permissions": {"read": True, "write": False, "delete": False, "execute": False, "git": False},
                    "enabled": False,
                },
            },
        }
        self.ws_store.path.parent.mkdir(parents=True, exist_ok=True)
        self.ws_store.path.write_text(json.dumps(ws_payload, indent=2), encoding="utf-8")

        # Legacy v1 managed_servers.json plus v1.0.2 OAuth & Settings
        legacy_servers = {
            "api_alpha": {
                "argv": [sys.executable, "-V"],
                "cwd": str(self.ws_root_alpha),
                "lifecycle": "controlled",
                "env": {"PORT": "8010"},
                "env_secret_refs": {"SRV_KEY": srv_secret_ref},
                "min_profile": "allowlist",
                "allowed_clients": ["client-rw", "client-ro"],
                "depends_on": ["shared_redis"],
            },
            "shared_redis": {
                "argv": [sys.executable, "-V"],
                "cwd": str(self.ws_root_beta),
                "lifecycle": "independent",
                "min_profile": "allowlist",
            },
            "matching_cwd_unlinked": {
                "argv": [sys.executable, "-V"],
                "cwd": str(self.ws_root_alpha),
                "lifecycle": "controlled",
                "min_profile": "full",
            },
            "ambiguous_nested_unlinked": {
                "argv": [sys.executable, "-V"],
                "cwd": str(self.ws_root_nested),
                "lifecycle": "independent",
                "min_profile": "full",
            },
        }
        self.srv_store.path.parent.mkdir(parents=True, exist_ok=True)
        self.srv_store.path.write_text(json.dumps(legacy_servers, indent=2), encoding="utf-8")

        oauth_path = self.root / "oauth" / "connections.sqlite3"
        oauth = OAuthStore(oauth_path, "https://mcp.example.com", "https://mcp.example.com/mcp")
        oauth.bind_owner("owner-secret-token")
        oauth.save_client(
            OAuthClientInformationFull(
                client_id="client-rw",
                client_name="Client RW",
                redirect_uris=["http://127.0.0.1:19001/cb"],
                token_endpoint_auth_method="none",
            )
        )
        oauth.mark_approved("client-rw")

        settings_path = self.root / "settings.json"
        settings_path.write_text(json.dumps({"theme_mode": "light", "language": "en"}), encoding="utf-8")

        # Run migration twice (must be lossless, atomic, idempotent, no process spawn)
        rep1 = self.coordinator.ensure_migrated()
        rep2 = self.coordinator.ensure_migrated()

        self.assertTrue(rep1["migrated_servers"] or rep1["migrated_workspaces"])
        self.assertFalse(rep2["migrated_servers"])
        self.assertFalse(rep2["migrated_workspaces"])
        self.assertEqual(self.srv_store.detect_schema_version(), 2)
        self.assertEqual(self.ws_store.detect_schema_version(), 2)
        self.assertTrue(self.srv_store.path.with_suffix(".json.v1.bak").is_file())
        self.assertTrue(self.ws_store.path.with_suffix(".json.v1.bak").is_file())

        # No auto-linking by matching cwd or overlapping path, no dummy workspace created
        workspaces = self.ws_store.load_workspaces()
        self.assertEqual(set(workspaces.keys()), {"ws_alpha", "ws_beta", "ws_disabled"})
        self.assertEqual(workspaces["ws_alpha"].linked_servers, ("api_alpha", "shared_redis", "ghost_srv"))
        self.assertEqual(workspaces["ws_alpha"].linked_tasks, ("task-001",))
        self.assertEqual(workspaces["ws_alpha"].linked_extensions, ("ext.alpha",))
        self.assertEqual(workspaces["ws_beta"].linked_servers, ("shared_redis",))

        snap = self.coordinator.partition_servers()
        self.assertEqual(
            [s.name for s in snap.unlinked_servers],
            ["ambiguous_nested_unlinked", "matching_cwd_unlinked"],
        )
        self.assertEqual(snap.missing_by_workspace["ws_alpha"], ("ghost_srv",))

        # Secrets, lifecycles, min_profile, OAuth & Settings preserved
        api_prof = self.srv_store.get_profile("api_alpha")
        assert api_prof is not None
        self.assertEqual(api_prof.lifecycle, "controlled")
        self.assertEqual(api_prof.depends_on, ("shared_redis",))
        merged_srv_env, _ = self.srv_store.resolve_profile_env(api_prof)
        self.assertEqual(merged_srv_env["SRV_KEY"], "srv-secret-value-alpha")
        merged_ws_env, _ = self.ws_store.resolve_workspace_env(workspaces["ws_alpha"])
        self.assertEqual(merged_ws_env["WS_KEY"], "ws-secret-value-alpha")

        self.assertIsNotNone(oauth.get_client("client-rw"))
        with patch.object(Settings, "path", return_value=settings_path):
            self.assertEqual(Settings.load().language, "en")

    def test_fault_injection_corrupt_state_fail_closed_and_concurrency(self) -> None:
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws1",
                name="WS1",
                root_path=str(self.ws_root_alpha),
                permissions=WorkspacePermissions(read=True, execute=True),
            )
        )
        self.srv_store.upsert_profile(_make_server("srv1", str(self.ws_root_alpha)))

        # Fault injection during atomic write keeps existing files intact
        before_ws = self.ws_store.path.read_text(encoding="utf-8")
        with patch("app.core.atomic_io.os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.coordinator.link_server("ws1", "srv1")
        self.assertEqual(self.ws_store.path.read_text(encoding="utf-8"), before_ws)
        leftovers = list(self.ws_store.path.parent.glob("*.tmp"))
        self.assertEqual(leftovers, [])

        # Corrupt JSON fails closed on load/upsert/authorize without overwriting corrupt files
        corrupt_ws = self.root / "corrupt_ws" / "workspaces.json"
        corrupt_ws.parent.mkdir(parents=True)
        corrupt_ws.write_text("{corrupt-json", encoding="utf-8")
        bad_ws_store = WorkspaceStore(corrupt_ws, secret_store=self.secret_store)
        bad_coord = WorkspaceServerCoordinator(bad_ws_store, self.srv_store)
        with self.assertRaises(ValueError):
            bad_coord.ensure_migrated()
        with self.assertRaises(ValueError):
            bad_ws_store.upsert_workspace(
                WorkspaceProfile(workspace_id="ws2", name="WS2", root_path=str(self.ws_root_beta))
            )
        with self.assertRaises(PermissionError):
            bad_coord.authorize_server_operation(
                "srv1", client_id="client-a", client_profile="full", mode="read"
            )
        self.assertEqual(corrupt_ws.read_text(encoding="utf-8"), "{corrupt-json")

        # Concurrent link + server creation under locks must not lose any entry
        for i in range(10):
            self.srv_store.upsert_profile(_make_server(f"conc_{i}", str(self.ws_root_alpha)))

        errors: list[BaseException] = []

        def worker(idx: int) -> None:
            try:
                c = WorkspaceServerCoordinator(
                    WorkspaceStore(self.ws_store.path, secret_store=self.secret_store),
                    ServerConfigStore(self.srv_store.path, secret_store=self.secret_store),
                )
                c.link_server("ws1", f"conc_{idx}")
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)
        self.assertEqual(errors, [])
        ws_after = self.ws_store.get_workspace("ws1")
        assert ws_after is not None
        self.assertEqual(set(ws_after.linked_servers), {f"conc_{i}" for i in range(10)})

    def test_link_unlink_delete_and_rename_semantics(self) -> None:
        ws_a = WorkspaceProfile(
            workspace_id="ws_a",
            name="A",
            root_path=str(self.ws_root_alpha),
            linked_servers=("api", "stale_ref"),
            permissions=WorkspacePermissions(read=True, execute=True),
        )
        ws_b = WorkspaceProfile(
            workspace_id="ws_b",
            name="B",
            root_path=str(self.ws_root_beta),
            linked_servers=("api",),
            permissions=WorkspacePermissions(read=True, execute=True),
        )
        self.ws_store.upsert_workspace(ws_a)
        self.ws_store.upsert_workspace(ws_b)

        ref = self.srv_store.set_env_secret("api", "API_TOKEN", "api-secret-xyz-123")
        self.srv_store.upsert_profile(
            _make_server(
                "api",
                str(self.ws_root_alpha),
                min_profile="full",
                allowed_clients=("c1",),
                env_secret_refs={"API_TOKEN": ref},
            )
        )
        self.srv_store.upsert_profile(
            _make_server("worker", str(self.ws_root_alpha), depends_on=("api",))
        )

        # Link is idempotent and does NOT widen server profile
        self.coordinator.link_server("ws_a", "api")
        self.assertEqual(self.ws_store.get_workspace("ws_a").linked_servers, ("api", "stale_ref"))  # type: ignore[union-attr]
        self.assertEqual(self.srv_store.get_profile("api").min_profile, "full")  # type: ignore[union-attr]
        self.assertEqual(self.srv_store.get_profile("api").allowed_clients, ("c1",))  # type: ignore[union-attr]

        # Rename updates profile ID, DPAPI secret ref, depends_on, and workspace linked_servers
        renamed = self.coordinator.rename_server("api", "api_v2")
        self.assertEqual(renamed.name, "api_v2")
        self.assertIsNone(self.srv_store.get_profile("api"))
        self.assertEqual(self.srv_store.get_profile("worker").depends_on, ("api_v2",))  # type: ignore[union-attr]
        self.assertEqual(self.ws_store.get_workspace("ws_a").linked_servers, ("api_v2", "stale_ref"))  # type: ignore[union-attr]
        self.assertEqual(self.ws_store.get_workspace("ws_b").linked_servers, ("api_v2",))  # type: ignore[union-attr]
        merged_env, _ = self.srv_store.resolve_profile_env(renamed)
        self.assertEqual(merged_env["API_TOKEN"], "api-secret-xyz-123")

        # Unlink stale_ref and api_v2 from ws_a without deleting or stopping server
        self.coordinator.unlink_server("ws_a", "stale_ref")
        self.coordinator.unlink_server("ws_a", "api_v2")
        self.assertEqual(self.ws_store.get_workspace("ws_a").linked_servers, ())  # type: ignore[union-attr]
        self.assertIsNotNone(self.srv_store.get_profile("api_v2"))

        # Delete ws_b preserves api_v2 and moves it to unlinked_servers
        self.assertTrue(self.coordinator.delete_workspace_preserving_servers("ws_b"))
        self.assertIsNone(self.ws_store.get_workspace("ws_b"))
        preserved = self.srv_store.get_profile("api_v2")
        assert preserved is not None
        self.assertEqual(preserved.min_profile, "full")
        self.assertIn("api_v2", [s.name for s in self.coordinator.partition_servers().unlinked_servers])

        # Delete depended server fails, then deleting worker + api_v2 cleans all links
        with self.assertRaises(ValueError):
            self.coordinator.delete_server_and_unlink("api_v2")
        self.coordinator.link_server("ws_a", "worker")
        self.assertTrue(self.coordinator.delete_server_and_unlink("worker"))
        self.assertEqual(self.ws_store.get_workspace("ws_a").linked_servers, ())  # type: ignore[union-attr]
        self.assertTrue(self.coordinator.delete_server_and_unlink("api_v2"))
        self.assertIsNone(self.srv_store.get_profile("api_v2"))

    def test_cross_layer_permission_matrix_and_confused_deputy_dependency(self) -> None:
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_alpha",
                name="Alpha",
                root_path=str(self.ws_root_alpha),
                linked_servers=("app_srv", "shared_srv"),
                permissions=WorkspacePermissions(read=True, execute=False),
                client_permissions={
                    "client-exec": WorkspacePermissions(read=True, execute=True),
                    "client-ro": WorkspacePermissions(read=True, execute=False),
                },
                allowed_clients=("client-exec", "client-ro"),
                min_profile="allowlist",
            )
        )
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_beta",
                name="Beta",
                root_path=str(self.ws_root_beta),
                linked_servers=("secret_dep", "shared_srv"),
                permissions=WorkspacePermissions(read=True, execute=True),
                allowed_clients=("client-beta",),
                min_profile="allowlist",
            )
        )
        self.srv_store.upsert_profile(
            _make_server(
                "secret_dep",
                str(self.ws_root_beta),
                min_profile="allowlist",
                allowed_clients=("client-beta", "client-exec"),
            )
        )
        self.srv_store.upsert_profile(
            _make_server(
                "app_srv",
                str(self.ws_root_alpha),
                min_profile="allowlist",
                allowed_clients=("client-exec", "client-ro"),
                depends_on=("secret_dep",),
            )
        )
        self.srv_store.upsert_profile(
            _make_server(
                "shared_srv",
                str(self.ws_root_alpha),
                min_profile="allowlist",
            )
        )
        self.srv_store.upsert_profile(
            _make_server("unlinked_srv", str(self.ws_root_alpha), min_profile="allowlist")
        )

        runner = ProcessRunner(spool_dir=self.root / "spool")
        mgr = ServerManager(
            self.srv_store,
            runner=runner,
            workspace_authorizer=self.coordinator.authorize_server_operation,
        )
        try:
            # Read vs control intersection
            self.assertEqual(
                mgr.status_server("app_srv", client_id="client-ro", client_profile="allowlist")["name"],
                "app_srv",
            )
            with self.assertRaises(PermissionError):
                mgr.start_server(
                    "app_srv",
                    client_id="client-ro",
                    client_profile="allowlist",
                    start_dependencies=False,
                    wait_readiness=False,
                )
            with self.assertRaises(PermissionError):
                mgr.start_server(
                    "app_srv",
                    client_id="client-exec",
                    client_profile="safe",
                    start_dependencies=False,
                    wait_readiness=False,
                )

            # Wrong workspace_id fails closed
            with self.assertRaises(PermissionError):
                mgr.status_server(
                    "app_srv",
                    client_id="client-exec",
                    client_profile="allowlist",
                    workspace_id="ws_beta",
                )

            # Multi-linked server: client-exec can access via ws_alpha, NOT via ws_beta
            st_shared = mgr.status_server(
                "shared_srv",
                client_id="client-exec",
                client_profile="allowlist",
            )
            self.assertEqual(st_shared["linked_workspaces"], ["ws_alpha"])
            with self.assertRaises(PermissionError):
                mgr.status_server(
                    "shared_srv",
                    client_id="client-exec",
                    client_profile="allowlist",
                    workspace_id="ws_beta",
                )

            # Confused deputy: client-exec is allowed on app_srv in ws_alpha, AND on secret_dep at Server layer,
            # BUT secret_dep is linked only to ws_beta where client-exec is NOT allowed -> must deny BEFORE spawning!
            with self.assertRaises(PermissionError):
                mgr.start_server(
                    "app_srv",
                    client_id="client-exec",
                    client_profile="allowlist",
                    start_dependencies=True,
                    wait_readiness=False,
                )
            self.assertFalse(mgr.status_server("secret_dep", client_id="owner")["running"])

            # Unlinked server remains manageable per ServerProfile rules
            started_unlinked = mgr.start_server(
                "unlinked_srv",
                client_id="client-exec",
                client_profile="allowlist",
                wait_readiness=False,
            )
            self.assertTrue(started_unlinked["running"])
            mgr.stop_server("unlinked_srv", client_id="client-exec", client_profile="allowlist")
        finally:
            mgr.close()
            runner.close()

    def test_n02_production_trust_gates_remain_strictly_blocked(self) -> None:
        self.assertEqual(PRODUCTION_TRUST_ROOTS, ())
        self.assertEqual(PRODUCTION_PUBLISHER_THUMBPRINTS, ())
        policy = TrustPolicy.production_default()
        self.assertFalse(policy.auto_install_permitted())
        self.assertEqual(policy.block_reason(), UpdateBlockReason.MISSING_TRUST_ROOTS)

        install_dir = self.root / "installed_app"
        install_dir.mkdir(parents=True)
        (install_dir / "MCPApp.exe").write_bytes(b"exe")
        (install_dir / "unins000.exe").write_bytes(b"unins")
        (install_dir / "unins000.dat").write_bytes(b"dat")
        env = detect_install_environment(
            app_dir=install_dir,
            frozen=True,
            current_version="1.0.2",
            rollback_cache_dir=self.root / "rollback_cache",
            policy=policy,
        )
        self.assertEqual(env.install_type, "installed")
        self.assertFalse(env.has_rollback_contract)
        self.assertIn(UpdateBlockReason.NO_ROLLBACK_CONTRACT, env.block_reasons)

        upd_dir = self.root / "updates"
        upd_dir.mkdir()
        state_path = upd_dir / "state.json"
        state_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "highest_seen_version": "1.0.2",
                    "active_transaction": {
                        "tx_id": "tx-1",
                        "state": UpdateState.SWAPPING,
                        "install_type": "portable",
                        "source_version": "1.0.2",
                        "target_version": "1.0.3",
                        "install_dir": str(install_dir),
                        "backup_dir": str(install_dir.with_name(".MCPApp-old-tx-1")),
                    },
                }
            ),
            encoding="utf-8",
        )
        rec = recover_interrupted_update_on_boot(
            state_path, upd_dir, install_dir=install_dir, policy=policy
        )
        self.assertIsNotNone(rec)
        assert rec is not None
        self.assertEqual(rec.state, UpdateState.BLOCKED)
        self.assertTrue(rec.error)


if __name__ == "__main__":
    unittest.main()
