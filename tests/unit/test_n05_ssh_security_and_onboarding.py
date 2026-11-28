"""TDD unit & local-fixture security tests for Stage N05 SSH device onboarding."""
from __future__ import annotations

import base64
import errno
import io
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import paramiko

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from backend.remote.discovery import (
    discover_ssh_endpoints_in_cidr,
    discover_tailscale_ssh_peers,
)
from backend.remote.host_keys import (
    HostKeyChangedError,
    HostKeyVerificationError,
    compute_host_key_sha256,
    inspect_known_hosts,
    probe_ssh_host_key,
    verify_independent_host_key,
)
from backend.remote.manager import RemoteManager
from backend.remote.models import (
    DevicePermissions,
    DeviceProfile,
    format_known_hosts_host,
    validate_host,
    validate_ssh_username,
)
from backend.remote.onboarding import (
    WizardDeviceConflictError,
    WizardStalePlanError,
    commit_device_wizard_plan,
    generate_ssh_ed25519_keypair,
    inspect_ssh_config,
    prepare_device_wizard_preview,
    probe_remote_os_and_capabilities,
    rotate_device_host_key,
    test_ssh_authentication,
)
from backend.remote.ssh_client import SSHAuthDiagnosticError, SSHConnectionManager
from backend.remote.store import DeviceStore, import_ssh_config
from tests.fixtures.local_ssh_server import LocalSSHServer


def _ed25519_pkey() -> paramiko.Ed25519Key:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode("ascii")
    return paramiko.Ed25519Key.from_private_key(io.StringIO(pem))


class N05ValidationAndModelsTests(unittest.TestCase):
    def test_validate_host_normalizes_ipv4_ipv6_dns_and_rejects_injections(self) -> None:
        self.assertEqual(validate_host("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_host("::1"), "::1")
        self.assertEqual(validate_host("[::1]"), "::1")
        self.assertEqual(validate_host("[2001:db8::5]"), "2001:db8::5")
        self.assertEqual(validate_host("srv-01.internal.example"), "srv-01.internal.example")
        self.assertEqual(format_known_hosts_host("::1", 22), "[::1]:22")
        self.assertEqual(format_known_hosts_host("127.0.0.1", 22), "127.0.0.1")
        self.assertEqual(format_known_hosts_host("127.0.0.1", 2222), "[127.0.0.1]:2222")

        bad_hosts = [
            "",
            "-oProxyCommand=calc",
            "-Jjump",
            "ssh://127.0.0.1",
            "user@127.0.0.1",
            "127.0.0.1:2222",
            "fe80::1%eth0",
            "0.0.0.0",
            "::",
            "255.255.255.255",
            "224.0.0.1",
            "ff02::1",
            "2130706433",
            "192.168.1.999",
            "bad\x00host",
            "bad\nhost",
            "bad host",
            "a" * 254,
        ]
        for bad in bad_hosts:
            with self.assertRaises(ValueError, msg=bad):
                validate_host(bad)

    def test_validate_ssh_username_and_strict_deserialization(self) -> None:
        self.assertEqual(validate_ssh_username("ops"), "ops")
        self.assertEqual(validate_ssh_username("deploy_1"), "deploy_1")
        self.assertEqual(validate_ssh_username(r"CORP\admin_user"), r"CORP\admin_user")
        self.assertEqual(validate_ssh_username("user@corp.local"), "user@corp.local")
        for bad_user in ("-oFoo", "u;id", "u&whoami", "u\x00x", "u\nx", "u x", "a" * 129):
            with self.assertRaises(ValueError, msg=bad_user):
                validate_ssh_username(bad_user)

        # Legacy dict without allow_oauth_clients preserves True for backward compatibility
        legacy = DeviceProfile.from_dict({
            "device_id": "leg1",
            "name": "Legacy",
            "host": "10.0.0.1",
        })
        self.assertTrue(legacy.allow_oauth_clients)

        # Malformed types MUST fail closed instead of truthy bool("false") coercion
        bad_dicts = [
            {"device_id": "x1", "host": "10.0.0.1", "enabled": "false"},
            {"device_id": "x1", "host": "10.0.0.1", "strict_host_key": "true"},
            {"device_id": "x1", "host": "10.0.0.1", "allow_oauth_clients": "false"},
            {"device_id": "x1", "host": "10.0.0.1", "permissions": {"execute": "false"}},
            {"device_id": "x1", "host": "10.0.0.1", "allowed_clients": "single-str"},
            {"device_id": "x1", "host": "10.0.0.1", "port": True},
        ]
        for rec in bad_dicts:
            with self.assertRaises(ValueError, msg=str(rec)):
                DeviceProfile.from_dict(rec)


class N05HostKeyAndAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.sftp_root = self.root / "sftp"
        self.sftp_root.mkdir()
        self.user_key = _ed25519_pkey()
        self.srv = LocalSSHServer(
            self.sftp_root,
            username="ciuser",
            password="cipass-secret",
            authorized_pubkeys=[self.user_key],
            host_key=_ed25519_pkey(),
        ).start()
        self.secrets = SecretStore(self.root / "secrets")
        self.store = DeviceStore(self.root / "remote" / "devices.json", secret_store=self.secrets)
        self.redactor = SecretRedactor()
        self.mgr = RemoteManager(self.store, redactor=self.redactor)

    def tearDown(self) -> None:
        self.mgr.close()
        self.srv.stop()
        self.tmp.cleanup()

    def test_preauth_host_key_probe_sends_zero_auth_packets_and_blocks_tofu(self) -> None:
        kh = self.root / "remote" / "known_hosts"
        probe = probe_ssh_host_key(
            self.srv.host,
            self.srv.port,
            known_hosts_path=kh,
            include_system_known_hosts=False,
        )
        self.assertEqual(probe.status, "unknown_host")
        self.assertEqual(probe.key_algorithm, self.srv.host_key.get_name())
        expected_fp = compute_host_key_sha256(self.srv.host_key)
        self.assertEqual(probe.fingerprint_sha256, expected_fp)
        self.assertEqual(self.srv.auth_attempts, [])

        # Blind TOFU without independent verification MUST fail
        with self.assertRaises(HostKeyVerificationError):
            verify_independent_host_key(
                probe,
                expected_fingerprint_input=expected_fp,
                verified_independently=False,
            )
        with self.assertRaises(HostKeyVerificationError):
            verify_independent_host_key(
                probe,
                expected_fingerprint_input="",
                verified_independently=True,
            )
        with self.assertRaises(HostKeyVerificationError):
            verify_independent_host_key(
                probe,
                expected_fingerprint_input="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                verified_independently=True,
            )

        # Accepts matching SHA256 fingerprint or OpenSSH .pub key line
        approved = verify_independent_host_key(
            probe,
            expected_fingerprint_input=f"{self.srv.host_key.get_name()} {self.srv.host_key.get_base64()} host@lab",
            verified_independently=True,
        )
        self.assertEqual(approved.fingerprint_sha256, expected_fp)

    def test_hashed_known_hosts_custom_port_and_mitm_key_substitution_before_auth(self) -> None:
        kh = self.root / "hashed_kh"
        hashed_host = paramiko.HostKeys.hash_host(format_known_hosts_host(self.srv.host, self.srv.port))
        hk = paramiko.HostKeys()
        hk.add(hashed_host, self.srv.host_key.get_name(), self.srv.host_key)
        hk.save(str(kh))

        check_same = inspect_known_hosts(
            self.srv.host,
            self.srv.port,
            self.srv.host_key,
            known_hosts_path=kh,
            include_system_known_hosts=False,
        )
        self.assertEqual(check_same.status, "trusted")

        # Different port MUST NOT inherit hashed trust
        check_other_port = inspect_known_hosts(
            self.srv.host,
            self.srv.port + 1,
            self.srv.host_key,
            known_hosts_path=kh,
            include_system_known_hosts=False,
        )
        self.assertEqual(check_other_port.status, "unknown_host")

        # Probe approves K1; then server rotates to K2 (MITM substitution)
        probe = probe_ssh_host_key(
            self.srv.host,
            self.srv.port,
            known_hosts_path=kh,
            include_system_known_hosts=False,
        )
        approved = verify_independent_host_key(
            probe,
            expected_fingerprint_input=probe.fingerprint_sha256,
            verified_independently=True,
        )
        self.srv.rotate_host_key(paramiko.RSAKey.generate(2048))
        self.srv.auth_attempts.clear()

        # Wizard auth test MUST abort BEFORE sending password/signature
        with self.assertRaises(PermissionError):
            test_ssh_authentication(
                self.srv.host,
                self.srv.port,
                self.srv.username,
                auth_method="password_ref",
                approved_host_key=approved,
                password="cipass-secret",
            )
        self.assertEqual(self.srv.auth_attempts, [])

        # Runtime SSHConnectionManager with pinned profile MUST also abort BEFORE auth
        pwd_ref = self.store.set_secret("pinned1", "password", "cipass-secret")
        self.store.upsert(
            DeviceProfile(
                device_id="pinned1",
                name="Pinned 1",
                host=self.srv.host,
                port=self.srv.port,
                username=self.srv.username,
                auth_method="password_ref",
                password_ref=pwd_ref,
                known_hosts_path=str(kh),
                pinned_host_key_algorithm=approved.key_algorithm,
                pinned_host_key_sha256=approved.fingerprint_sha256,
                pinned_host_key_base64=approved.public_key_base64,
                permissions=DevicePermissions(execute=True),
            )
        )
        with self.assertRaises(PermissionError):
            self.mgr.device_health("pinned1")
        self.assertEqual(self.srv.auth_attempts, [])

        # Host key changed probe raises HostKeyChangedError and cannot bypass without allow_rotation
        probe_changed = probe_ssh_host_key(
            self.srv.host,
            self.srv.port,
            known_hosts_path=kh,
            include_system_known_hosts=False,
        )
        self.assertEqual(probe_changed.status, "host_key_changed")
        with self.assertRaises(HostKeyChangedError):
            verify_independent_host_key(
                probe_changed,
                expected_fingerprint_input=probe_changed.fingerprint_sha256,
                verified_independently=True,
                allow_rotation=False,
            )

    def test_strict_auth_isolation_no_implicit_fallback_and_keygen(self) -> None:
        kh = self.srv.write_known_hosts(self.root / "kh")
        probe = probe_ssh_host_key(
            self.srv.host, self.srv.port, known_hosts_path=kh, include_system_known_hosts=False
        )
        approved = verify_independent_host_key(
            probe, expected_fingerprint_input=probe.fingerprint_sha256, verified_independently=True
        )

        # Generate Ed25519 keypair with passphrase, refuse overwrite
        key_path = self.root / "keys" / "id_ed25519_test"
        gen = generate_ssh_ed25519_keypair(key_path, passphrase="key-pass-canary", comment="test@mcp")
        self.assertTrue(gen.public_key_line.startswith("ssh-ed25519 "))
        self.assertTrue(gen.fingerprint_sha256.startswith("SHA256:"))
        self.assertNotIn("PRIVATE KEY", gen.public_key_line)
        with self.assertRaises(FileExistsError):
            generate_ssh_ed25519_keypair(key_path)

        # Missing/wrong passphrase returns explicit diagnostic without falling back to agent
        with self.assertRaises(SSHAuthDiagnosticError) as ctx_need:
            test_ssh_authentication(
                self.srv.host,
                self.srv.port,
                self.srv.username,
                auth_method="key",
                approved_host_key=approved,
                key_path=str(key_path),
                passphrase="",
            )
        self.assertEqual(ctx_need.exception.code, "key_passphrase_required")
        with self.assertRaises(SSHAuthDiagnosticError) as ctx_bad:
            test_ssh_authentication(
                self.srv.host,
                self.srv.port,
                self.srv.username,
                auth_method="key",
                approved_host_key=approved,
                key_path=str(key_path),
                passphrase="wrong",
            )
        self.assertEqual(ctx_bad.exception.code, "key_passphrase_invalid")

        # Key auth works when server authorizes the generated public key, and never calls agent
        gen_pub = paramiko.Ed25519Key.from_private_key_file(str(key_path), password="key-pass-canary")
        self.srv.authorized_pubkeys = (gen_pub,)
        real_cli = paramiko.SSHClient()
        with patch("backend.remote.ssh_client.paramiko.SSHClient") as cli_cls:
            cli_cls.return_value = real_cli
            with patch.object(real_cli, "connect", wraps=real_cli.connect) as wrap_connect:
                test_ssh_authentication(
                    self.srv.host,
                    self.srv.port,
                    self.srv.username,
                    auth_method="key",
                    approved_host_key=approved,
                    key_path=str(key_path),
                    passphrase="key-pass-canary",
                )
                kw = wrap_connect.call_args.kwargs
                self.assertFalse(kw["allow_agent"])
                self.assertFalse(kw["look_for_keys"])
                self.assertIsNone(kw["password"])

        # Agent mode fails cleanly when agent has no keys without scanning ~/.ssh/id_*
        empty_agent = MagicMock()
        empty_agent.get_keys.return_value = ()
        with patch("backend.remote.ssh_client.paramiko.Agent", return_value=empty_agent):
            with self.assertRaises(SSHAuthDiagnosticError) as ctx_agent:
                test_ssh_authentication(
                    self.srv.host,
                    self.srv.port,
                    self.srv.username,
                    auth_method="agent",
                    approved_host_key=approved,
                )
            self.assertEqual(ctx_agent.exception.code, "agent_unavailable")

    def test_os_and_capability_detection_windows_linux_unknown(self) -> None:
        kh = self.srv.write_known_hosts(self.root / "kh")
        probe = probe_ssh_host_key(
            self.srv.host, self.srv.port, known_hosts_path=kh, include_system_known_hosts=False
        )
        approved = verify_independent_host_key(
            probe, expected_fingerprint_input=probe.fingerprint_sha256, verified_independently=True
        )
        ssh_mgr = SSHConnectionManager(self.store)

        # Linux + SFTP
        res_lin = probe_remote_os_and_capabilities(
            ssh_mgr,
            self.srv.host,
            self.srv.port,
            self.srv.username,
            auth_method="password_ref",
            approved_host_key=approved,
            password="cipass-secret",
        )
        self.assertEqual(res_lin.detected_os, "linux")
        self.assertIn("sftp", res_lin.capabilities)

        # Windows + SFTP disabled
        with LocalSSHServer(
            self.sftp_root,
            username="winuser",
            password="winpass-secret",
            os_flavor="windows",
            enable_sftp=False,
        ) as win_srv:
            w_kh = win_srv.write_known_hosts(self.root / "w_kh")
            w_probe = probe_ssh_host_key(
                win_srv.host, win_srv.port, known_hosts_path=w_kh, include_system_known_hosts=False
            )
            w_app = verify_independent_host_key(
                w_probe, expected_fingerprint_input=w_probe.fingerprint_sha256, verified_independently=True
            )
            res_win = probe_remote_os_and_capabilities(
                ssh_mgr,
                win_srv.host,
                win_srv.port,
                win_srv.username,
                auth_method="password_ref",
                approved_host_key=w_app,
                password="winpass-secret",
            )
            self.assertEqual(res_win.detected_os, "windows")
            self.assertNotIn("sftp", res_win.capabilities)

        # Unknown OS MUST stay 'unknown', never assumed 'linux'
        with LocalSSHServer(
            self.sftp_root,
            username="bsd",
            password="bsdpass-secret",
            os_flavor="unknown",
        ) as unk_srv:
            u_kh = unk_srv.write_known_hosts(self.root / "u_kh")
            u_probe = probe_ssh_host_key(
                unk_srv.host, unk_srv.port, known_hosts_path=u_kh, include_system_known_hosts=False
            )
            u_app = verify_independent_host_key(
                u_probe, expected_fingerprint_input=u_probe.fingerprint_sha256, verified_independently=True
            )
            res_unk = probe_remote_os_and_capabilities(
                ssh_mgr,
                unk_srv.host,
                unk_srv.port,
                unk_srv.username,
                auth_method="password_ref",
                approved_host_key=u_app,
                password="bsdpass-secret",
            )
            self.assertEqual(res_unk.detected_os, "unknown")


class N05ImportDiscoveryAndPermissionsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.sftp_root = self.root / "sftp"
        self.sftp_root.mkdir()
        self.secrets = SecretStore(self.root / "secrets")
        self.store = DeviceStore(self.root / "remote" / "devices.json", secret_store=self.secrets)
        self.redactor = SecretRedactor()
        self.srv = LocalSSHServer(self.sftp_root, username="ops", password="canary-ssh-password-999").start()
        self.redactor.register("canary-ssh-password-999")
        self.mgr = RemoteManager(self.store, redactor=self.redactor)

    def tearDown(self) -> None:
        self.mgr.close()
        self.srv.stop()
        self.tmp.cleanup()

    def test_ssh_config_inspect_and_import_rejects_exec_directives_and_duplicates(self) -> None:
        cfg = self.root / "ssh_config"
        cfg.write_text(
            """
# permission=full trust=yes
Host *
    User bad
    ProxyCommand evil-cmd

Match exec "echo pwned"
    User match_user

Host !blocked srv-ok
    HostName 127.0.0.1
    User ops
    Port 2222
    ProxyJump bastion
    RemoteCommand rm -rf /
    LocalCommand calc.exe
    Include /tmp/other.conf
    IdentityFile ~/.ssh/nonexistent_test_key
""",
            encoding="utf-8",
        )
        self.store.upsert(DeviceProfile(device_id="existing_dup", name="Existing", host="10.0.0.5"))
        cfg2 = self.root / "ssh_config2"
        cfg2.write_text(
            cfg.read_text(encoding="utf-8") + "\nHost existing_dup\n  HostName 10.0.0.5\n",
            encoding="utf-8",
        )
        report = inspect_ssh_config(cfg2, existing_store=self.store)
        names = {c.profile.device_id for c in report.candidates}
        self.assertEqual(names, {"srv-ok", "existing_dup"})
        srv_ok = next(c for c in report.candidates if c.profile.device_id == "srv-ok")
        self.assertFalse(srv_ok.profile.allow_oauth_clients)
        self.assertFalse(srv_ok.profile.permissions.execute)
        self.assertTrue(any("ProxyJump" in d or "RemoteCommand" in d or "LocalCommand" in d for d in srv_ok.diagnostics))
        dup = next(c for c in report.candidates if c.profile.device_id == "existing_dup")
        self.assertTrue(dup.is_duplicate)
        self.assertTrue(any("Match" in w or "ProxyCommand" in w for w in report.warnings))
        imported = import_ssh_config(cfg)
        self.assertEqual([p.device_id for p in imported], ["srv-ok"])
        self.assertFalse(imported[0].allow_oauth_clients)

    def test_opt_in_cidr_and_tailscale_discovery_bounds(self) -> None:
        with self.assertRaises(PermissionError):
            discover_ssh_endpoints_in_cidr("127.0.0.1/32", ports=(self.srv.port,), owner_consent=False)
        for bad_scope in ("8.8.8.0/24", "10.0.0.0/16", "2001:db8::/64", "example.com"):
            with self.assertRaises(ValueError, msg=bad_scope):
                discover_ssh_endpoints_in_cidr(bad_scope, ports=(22,), owner_consent=True)

        # Find an unused port on loopback
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            closed_port = int(s.getsockname()[1])

        found = discover_ssh_endpoints_in_cidr(
            "127.0.0.1/32",
            ports=(self.srv.port, closed_port),
            owner_consent=True,
        )
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].host, "127.0.0.1")
        self.assertEqual(found[0].port, self.srv.port)
        self.assertFalse(found[0].trusted)
        self.assertFalse(found[0].authenticated)

        # Tailscale requires consent and never runs login/up
        with self.assertRaises(PermissionError):
            discover_tailscale_ssh_peers(owner_consent=False)
        with patch("backend.remote.discovery._find_tailscale", return_value=""):
            res_missing = discover_tailscale_ssh_peers(owner_consent=True)
            self.assertFalse(res_missing.available)
            self.assertEqual(res_missing.status, "not_available")

        sample_json = json.dumps({
            "BackendState": "Running",
            "Peer": {
                "p1": {
                    "HostName": "linux-node",
                    "DNSName": "linux-node.tailnet.ts.net.",
                    "TailscaleIPs": ["100.64.0.10", "fd7a:115c:a1e0::10"],
                    "OS": "linux",
                    "Online": True,
                }
            },
        })
        with patch("backend.remote.discovery._find_tailscale", return_value="tailscale"), patch(
            "backend.remote.discovery.run_cli_capture", return_value=(0, sample_json, "")
        ) as mock_cli:
            res_ts = discover_tailscale_ssh_peers(owner_consent=True)
            self.assertTrue(res_ts.available)
            self.assertEqual(len(res_ts.peers), 1)
            self.assertEqual(res_ts.peers[0].ip, "100.64.0.10")
            self.assertEqual(mock_cli.call_args.args[0], ["tailscale", "status", "--json"])

    def test_atomic_wizard_commit_rollback_stale_plan_and_oauth_deny_by_default(self) -> None:
        probe = probe_ssh_host_key(
            self.srv.host,
            self.srv.port,
            known_hosts_path=self.store.managed_known_hosts_path,
            include_system_known_hosts=False,
        )
        approved = verify_independent_host_key(
            probe, expected_fingerprint_input=probe.fingerprint_sha256, verified_independently=True
        )
        draft = DeviceProfile(
            device_id="wiz_box",
            name="Wizard Box",
            host=self.srv.host,
            port=self.srv.port,
            username="ops",
            auth_method="password_ref",
            allow_oauth_clients=False,
            permissions=DevicePermissions(),
            detected_os="linux",
            detected_capabilities=("sftp",),
        )
        preview = prepare_device_wizard_preview(
            self.store,
            draft,
            approved_host_key=approved,
            password="canary-ssh-password-999",
        )
        # Redaction: canary secret must not appear anywhere in preview
        self.assertNotIn("canary-ssh-password-999", preview.summary_text)

        # Stale plan rejected if draft changes after preview
        mutated = DeviceProfile(
            device_id="wiz_box",
            name="Wizard Box",
            host=self.srv.host,
            port=self.srv.port + 1,
            username="ops",
            auth_method="password_ref",
            allow_oauth_clients=False,
            permissions=DevicePermissions(),
        )
        with self.assertRaises(WizardStalePlanError):
            commit_device_wizard_plan(
                self.store,
                mutated,
                approved_host_key=approved,
                expected_snapshot=preview.snapshot,
                password="canary-ssh-password-999",
            )
        self.assertEqual(self.store.load_all(), {})

        # Fault injection (ENOSPC on devices.json replace) rolls back known_hosts and secrets
        with patch("app.core.atomic_io.os.replace", side_effect=OSError(errno.ENOSPC, "Disk full")):
            with self.assertRaises(OSError):
                commit_device_wizard_plan(
                    self.store,
                    draft,
                    approved_host_key=approved,
                    expected_snapshot=preview.snapshot,
                    password="canary-ssh-password-999",
                )
        self.assertFalse(self.store.path.exists())
        self.assertFalse(self.store.managed_known_hosts_path.exists())
        self.assertEqual(self.secrets.list_keys("ssh"), [])

        # Clean commit succeeds
        committed = commit_device_wizard_plan(
            self.store,
            draft,
            approved_host_key=approved,
            expected_snapshot=preview.snapshot,
            password="canary-ssh-password-999",
        )
        self.assertFalse(committed.allow_oauth_clients)
        self.assertTrue(committed.known_hosts_path)
        self.assertNotIn("canary-ssh-password-999", self.store.path.read_text(encoding="utf-8"))
        self.assertNotIn("canary-ssh-password-999", self.store.managed_known_hosts_path.read_text(encoding="utf-8"))

        # Duplicate commit fails cleanly
        with self.assertRaises(WizardDeviceConflictError):
            prepare_device_wizard_preview(
                self.store,
                draft,
                approved_host_key=approved,
                password="canary-ssh-password-999",
            )

        # Deny-by-default OAuth isolation even for 'full' client when allow_oauth_clients=False
        self.assertEqual(
            self.mgr.list_devices(client_id="c-full", client_profile="full", from_oauth=True)["devices"],
            [],
        )
        for fn in (
            lambda: self.mgr.device_info("wiz_box", client_id="c-full", client_profile="full", from_oauth=True),
            lambda: self.mgr.device_health("wiz_box", client_id="c-full", client_profile="full", from_oauth=True),
            lambda: self.mgr.ssh_execute("wiz_box", "uname -s -m", client_id="c-full", client_profile="full", from_oauth=True),
            lambda: self.mgr.device_health("wiz_box", client_id="owner", client_profile="full", from_oauth=True),
        ):
            with self.assertRaises(PermissionError):
                fn()

        # Owner GUI (from_oauth=False) can probe health directly
        h = self.mgr.device_health("wiz_box", client_id="owner", client_profile="full", from_oauth=False)
        self.assertTrue(h["reachable"])

        # Host-key rotation updates known_hosts and pin atomically
        new_k = _ed25519_pkey()
        self.srv.rotate_host_key(new_k)
        rot_probe = probe_ssh_host_key(
            self.srv.host,
            self.srv.port,
            known_hosts_path=self.store.managed_known_hosts_path,
            include_system_known_hosts=False,
        )
        rot_approved = verify_independent_host_key(
            rot_probe,
            expected_fingerprint_input=rot_probe.fingerprint_sha256,
            verified_independently=True,
            allow_rotation=True,
        )
        rotated_dev = rotate_device_host_key(self.store, "wiz_box", rot_approved)
        self.assertEqual(rotated_dev.pinned_host_key_sha256, rot_approved.fingerprint_sha256)
        self.assertTrue(self.mgr.device_health("wiz_box")["reachable"])

        # Live revoke blocks ssh_execute via live_client_authorizer AND before ssh_task_start worker executes
        revoked_mgr = RemoteManager(
            self.store,
            redactor=self.redactor,
            live_client_authorizer=lambda cid: (_ for _ in ()).throw(PermissionError("Revoked")),
        )
        try:
            with self.assertRaises(PermissionError):
                revoked_mgr.list_devices(client_id="c-full", client_profile="full", from_oauth=True)
        finally:
            revoked_mgr.close()

        # Simulate allowlisted client revoked right after ssh_task_start dispatch
        self.store.upsert(
            DeviceProfile(
                device_id="wiz_box_oauth",
                name="Wizard OAuth",
                host=self.srv.host,
                port=self.srv.port,
                username="ops",
                auth_method="password_ref",
                password_ref=committed.password_ref,
                known_hosts_path=str(self.store.managed_known_hosts_path),
                pinned_host_key_algorithm=rotated_dev.pinned_host_key_algorithm,
                pinned_host_key_sha256=rotated_dev.pinned_host_key_sha256,
                pinned_host_key_base64=rotated_dev.pinned_host_key_base64,
                allow_oauth_clients=True,
                allowed_commands=("uname -s -m",),
                permissions=DevicePermissions(execute=True),
            )
        )
        auth_calls = {"n": 0}

        def _revoke_after_first(cid: str, _tool: str = "") -> str:
            auth_calls["n"] += 1
            if auth_calls["n"] == 1:
                return "allowlist"
            raise PermissionError("Client revoked in flight")

        task_mgr = RemoteManager(self.store, redactor=self.redactor, live_client_authorizer=_revoke_after_first)
        try:
            job = task_mgr.ssh_task_start(
                "wiz_box_oauth",
                "uname -s -m",
                client_id="c-allow",
                client_profile="allowlist",
                from_oauth=True,
            )
            deadline = time.monotonic() + 5.0
            st = job
            while time.monotonic() < deadline:
                st = task_mgr.job_status(job["job_id"])
                if st["state"] != "running":
                    break
                time.sleep(0.02)
            self.assertEqual(st["state"], "failed")
            self.assertIn("revoked", st["output"].lower())
        finally:
            task_mgr.close()

    def test_wal_crash_recovery_legacy_rotation_cancellation_legacy_sync_and_ipv6(self) -> None:
        # 1. WAL crash recovery restores preimages, deletes orphan secret, and removes tx journal
        preimage_json = json.dumps({"version": 2, "devices": {}}).encode("utf-8")
        self.store.path.write_bytes(b"{CORRUPTED_UNFINISHED_TX")
        self.secrets.set_secret("ssh", "orphan_dev__password__deadbeef", "secret-val")
        self.store.tx_journal_path.write_text(
            json.dumps({
                "schema_version": 1,
                "files": [
                    {
                        "path": str(self.store.path),
                        "existed": True,
                        "content_b64": base64.b64encode(preimage_json).decode("ascii"),
                    },
                    {
                        "path": str(self.store.managed_known_hosts_path),
                        "existed": False,
                        "content_b64": None,
                    },
                ],
                "created_secrets": [["ssh", "orphan_dev__password__deadbeef"]],
            }),
            encoding="utf-8",
        )
        self.store.managed_known_hosts_path.write_text("stale", encoding="utf-8")
        self.assertEqual(self.store.load_all(strict=True), {})
        self.assertFalse(self.store.tx_journal_path.exists())
        self.assertFalse(self.store.managed_known_hosts_path.exists())
        self.assertEqual(self.secrets.list_keys("ssh"), [])

        # 2. Legacy device pointing to external known_hosts -> rotation updates managed known_hosts without modifying external file
        ext_kh = self.root / "external_legacy_kh"
        self.srv.write_known_hosts(ext_kh)
        ext_before = ext_kh.read_text(encoding="utf-8")
        pwd_ref = self.store.set_secret("legacy_dev", "password", "canary-ssh-password-999")
        self.store.upsert(
            DeviceProfile(
                device_id="legacy_dev",
                name="Legacy Dev",
                host=self.srv.host,
                port=self.srv.port,
                username=self.srv.username,
                auth_method="password_ref",
                password_ref=pwd_ref,
                known_hosts_path=str(ext_kh),
                allow_oauth_clients=True,
                permissions=DevicePermissions(execute=True),
            )
        )
        self.srv.rotate_host_key(_ed25519_pkey())
        rot_probe = probe_ssh_host_key(
            self.srv.host, self.srv.port, known_hosts_path=ext_kh, include_system_known_hosts=False
        )
        self.assertEqual(rot_probe.status, "host_key_changed")
        approved_rot = verify_independent_host_key(
            rot_probe,
            expected_fingerprint_input=rot_probe.fingerprint_sha256,
            verified_independently=True,
            allow_rotation=True,
        )
        rotated = rotate_device_host_key(self.store, "legacy_dev", approved_rot)
        self.assertEqual(Path(rotated.known_hosts_path), self.store.managed_known_hosts_path)
        self.assertEqual(ext_kh.read_text(encoding="utf-8"), ext_before)
        self.assertTrue(self.mgr.device_health("legacy_dev")["reachable"])

        # 3. Cancelled pre-auth probe exits cleanly
        ev = threading.Event()
        ev.set()
        with self.assertRaises(TimeoutError):
            probe_ssh_host_key(self.srv.host, self.srv.port, cancel_event=ev)

        # 4. Legacy _sync_ssh_exec rejects host/user option injection
        from backend.server import _sync_ssh_exec

        with self.assertRaises(ValueError):
            _sync_ssh_exec("-oProxyCommand=calc.exe", "ops", "echo ok", 22, 5)
        with self.assertRaises(ValueError):
            _sync_ssh_exec("127.0.0.1", "-oBad", "echo ok", 22, 5)

        # 5. IPv6 known_hosts formatting & canonical matching work regardless of firewall policy
        v6_kh = self.root / "v6_kh"
        v6_key = _ed25519_pkey()
        hk_v6 = paramiko.HostKeys()
        hk_v6.add(format_known_hosts_host("::1", 2222), v6_key.get_name(), v6_key)
        hk_v6.save(str(v6_kh))
        self.assertEqual(
            inspect_known_hosts("::1", 2222, v6_key, known_hosts_path=v6_kh, include_system_known_hosts=False).status,
            "trusted",
        )

    def test_ipv6_loopback_host_key_probe_when_permitted(self) -> None:
        try:
            probe_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            probe_sock.bind(("::1", 0))
            probe_sock.close()
        except OSError as exc:
            self.skipTest(f"IPv6 loopback bind unavailable: {exc}")
        v6_srv = LocalSSHServer(
            self.sftp_root,
            username="ops",
            password="canary-ssh-password-999",
            bind_host="::1",
        ).start()
        try:
            try:
                v6_probe = probe_ssh_host_key("::1", v6_srv.port, include_system_known_hosts=False)
            except (PermissionError, OSError) as exc:
                self.skipTest(f"IPv6 loopback connect blocked by host environment: {exc}")
            self.assertEqual(v6_probe.endpoint_ip, "::1")
            v6_approved = verify_independent_host_key(
                v6_probe, expected_fingerprint_input=v6_probe.fingerprint_sha256, verified_independently=True
            )
            auth_res = test_ssh_authentication(
                "::1",
                v6_srv.port,
                "ops",
                auth_method="password_ref",
                approved_host_key=v6_approved,
                password="canary-ssh-password-999",
            )
            self.assertTrue(auth_res["ok"])
        finally:
            v6_srv.stop()


if __name__ == "__main__":
    unittest.main()
