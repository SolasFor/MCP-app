"""Unit tests for Stage 6 Server Manager: migration, templates, SecretStore, DAG, ports, access."""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.core.secret_store import SecretStore
from backend.servers.models import ReadinessConfig, RestartConfig, ServerProfile
from backend.servers.probes import check_port_conflict
from backend.servers.store import ServerConfigStore, resolve_start_order, validate_dependencies
from backend.servers.templates import build_profile_from_template, list_templates


class ServerManagerUnitTests(unittest.TestCase):
    def test_lossless_legacy_v1_migration_and_secret_storage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg_path = root / "managed_servers.json"
            legacy = {
                "api": {
                    "argv": [sys.executable, "-m", "http.server", "8011"],
                    "cwd": tmp,
                    "lifecycle": "controlled",
                },
                "gui_app": {
                    "argv": [sys.executable, "-c", "import time; time.sleep(1)"],
                    "cwd": tmp,
                    "lifecycle": "independent",
                },
            }
            cfg_path.write_text(json.dumps(legacy), encoding="utf-8")

            secret_store = SecretStore(root / "secrets")
            store = ServerConfigStore(cfg_path, secret_store=secret_store)
            self.assertEqual(store.detect_schema_version(), 1)
            report = store.migrate_legacy_file(create_backup=True)

            self.assertEqual(report["imported"], ["api", "gui_app"])
            self.assertTrue(Path(report["backup_path"]).is_file())
            self.assertEqual(store.detect_schema_version(), 2)

            profiles = store.load_profiles()
            self.assertEqual(list(profiles["api"].argv), legacy["api"]["argv"])
            self.assertEqual(profiles["api"].lifecycle, "controlled")
            self.assertEqual(profiles["gui_app"].lifecycle, "independent")
            self.assertEqual(profiles["api"].min_profile, "full")

            ref = store.set_env_secret("api", "API_SECRET", "s3cr3t-value-xyz")
            updated = ServerProfile(
                name="api",
                argv=profiles["api"].argv,
                cwd=profiles["api"].cwd,
                lifecycle="controlled",
                env={"MODE": "dev"},
                env_secret_refs={"API_SECRET": ref},
            )
            store.upsert_profile(updated)

            raw_json = cfg_path.read_text(encoding="utf-8")
            self.assertNotIn("s3cr3t-value-xyz", raw_json)
            self.assertIn("secret://servers/api__API_SECRET", raw_json)

            merged, secrets_list = store.resolve_profile_env(store.get_profile("api"))  # type: ignore[arg-type]
            self.assertEqual(merged["MODE"], "dev")
            self.assertEqual(merged["API_SECRET"], "s3cr3t-value-xyz")
            self.assertIn("s3cr3t-value-xyz", secrets_list)

    def test_dependency_topological_sort_and_cycle_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p_db = ServerProfile(name="db", argv=(sys.executable, "-V"), cwd=tmp)
            p_cache = ServerProfile(name="cache", argv=(sys.executable, "-V"), cwd=tmp, depends_on=("db",))
            p_api = ServerProfile(name="api", argv=(sys.executable, "-V"), cwd=tmp, depends_on=("cache", "db"))
            profiles = {"api": p_api, "cache": p_cache, "db": p_db}

            order = resolve_start_order(profiles, "api")
            self.assertEqual(order, ["db", "cache", "api"])

            cyc_a = ServerProfile(name="a", argv=(sys.executable, "-V"), cwd=tmp, depends_on=("b",))
            cyc_b = ServerProfile(name="b", argv=(sys.executable, "-V"), cwd=tmp, depends_on=("a",))
            with self.assertRaises(ValueError):
                validate_dependencies({"a": cyc_a, "b": cyc_b})

            missing = ServerProfile(name="web", argv=(sys.executable, "-V"), cwd=tmp, depends_on=("nope",))
            with self.assertRaises(ValueError):
                validate_dependencies({"web": missing})

    def test_templates_validate_params_and_enforce_loopback_defaults(self) -> None:
        names = {item["template"] for item in list_templates()}
        self.assertEqual(
            names,
            {"python_fastapi", "python_flask", "node_express", "vite_next", "docker_compose", "static_http", "custom"},
        )

        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = Path(tmp) / ("tool.exe" if os.name == "nt" else "tool")
            fake_bin.write_text("", encoding="utf-8")
            fake_node = Path(tmp) / ("node.exe" if os.name == "nt" else "node")
            fake_node.write_text("", encoding="utf-8")
            fake_docker = Path(tmp) / ("docker.exe" if os.name == "nt" else "docker")
            fake_docker.write_text("", encoding="utf-8")

            p_fast = build_profile_from_template(
                name="fastapi_svc", template="python_fastapi", cwd=tmp, executable=sys.executable, port=8005
            )
            self.assertEqual(p_fast.host, "127.0.0.1")
            self.assertEqual(p_fast.readiness.kind, "http")
            self.assertIn("uvicorn", p_fast.argv)

            p_flask = build_profile_from_template(
                name="flask_svc", template="python_flask", cwd=tmp, executable=sys.executable, entrypoint="wsgi:app"
            )
            self.assertIn("--no-debugger", p_flask.argv)

            p_node = build_profile_from_template(
                name="node_svc", template="node_express", cwd=tmp, executable=str(fake_node), entrypoint="src/index.js"
            )
            self.assertEqual(p_node.env["HOST"], "127.0.0.1")

            p_vite = build_profile_from_template(
                name="vite_svc", template="vite_next", cwd=tmp, executable=str(fake_node), entrypoint="vite"
            )
            self.assertEqual(p_vite.port, 5173)
            self.assertNotIn("npm", p_vite.argv[0].lower())

            p_doc = build_profile_from_template(
                name="compose_svc", template="docker_compose", cwd=tmp, executable=str(fake_docker), entrypoint="compose.yml:web"
            )
            self.assertIn("--no-build", p_doc.argv)

            p_stat = build_profile_from_template(
                name="static_svc", template="static_http", cwd=tmp, executable=sys.executable, port=8090
            )
            self.assertIn("http.server", p_stat.argv)

            # Security rejections: shell metacharacters, traversal, non-loopback bind, disallowed binaries
            with self.assertRaises(ValueError):
                build_profile_from_template(
                    name="bad1", template="python_fastapi", cwd=tmp, executable=sys.executable, entrypoint="app:app;whoami"
                )
            with self.assertRaises(ValueError):
                build_profile_from_template(
                    name="bad2", template="node_express", cwd=tmp, executable=str(fake_node), entrypoint="../evil.js"
                )
            with self.assertRaises(ValueError):
                build_profile_from_template(
                    name="bad3", template="python_fastapi", cwd=tmp, executable=sys.executable, host="0.0.0.0"
                )
            with self.assertRaises(ValueError):
                npm_fake = Path(tmp) / ("npm.cmd" if os.name == "nt" else "npm")
                npm_fake.write_text("", encoding="utf-8")
                build_profile_from_template(
                    name="bad4", template="vite_next", cwd=tmp, executable=str(npm_fake), entrypoint="vite"
                )

    def test_port_conflict_detects_live_socket_without_touching_it(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        try:
            port = sock.getsockname()[1]
            conflict = check_port_conflict("127.0.0.1", port, owned_pids=())
            self.assertIsNotNone(conflict)
            self.assertEqual(conflict["port"], port)  # type: ignore[index]
            # Socket must remain alive and bound; check_port_conflict never closes/kills foreign PIDs.
            self.assertEqual(sock.getsockname()[1], port)

            # When our own PID owns the port (and psutil returns it), no conflict is reported.
            with patch("backend.servers.probes.psutil.net_connections") as mock_conns:
                mock_conns.return_value = [
                    type("Conn", (), {
                        "status": "LISTEN",
                        "pid": os.getpid(),
                        "laddr": type("Addr", (), {"ip": "127.0.0.1", "port": port})(),
                    })()
                ]
                self.assertIsNone(check_port_conflict("127.0.0.1", port, owned_pids={os.getpid()}))
        finally:
            sock.close()

    def test_profile_serialization_roundtrip(self) -> None:
        prof = ServerProfile(
            name="svc_one",
            display_name="Service One",
            template="custom",
            argv=(sys.executable, "-V"),
            cwd=tempfile.gettempdir(),
            host="127.0.0.1",
            port=9001,
            readiness=ReadinessConfig(kind="http", host="127.0.0.1", port=9001, http_path="/health"),
            restart=RestartConfig(policy="on-failure", max_attempts=3, base_backoff_seconds=0.5),
            min_profile="allowlist",
            allowed_clients=("client-a",),
        )
        restored = ServerProfile.from_dict("svc_one", prof.to_dict())
        self.assertEqual(restored.to_dict(), prof.to_dict())


if __name__ == "__main__":
    unittest.main()
