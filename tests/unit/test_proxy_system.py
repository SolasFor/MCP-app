"""Unit tests for the Wave 2 proxy system (none default, auto-detect, manual, SOCKS5/SOCKS5H/HTTP CONNECT)."""
from __future__ import annotations

import base64
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from app.config import PROVIDER_NGROK, Settings
from app.core import proxy as px
from app.core.service_manager import ServiceManager


def _start_dummy_port() -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def accept_and_close() -> None:
        while True:
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                break

    threading.Thread(target=accept_and_close, daemon=True).start()
    return srv, srv.getsockname()[1]


def _start_mock_target() -> tuple[socket.socket, int, list[bytes]]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    seen: list[bytes] = []

    def loop() -> None:
        while True:
            try:
                conn, _ = srv.accept()
                conn.settimeout(1.0)
                try:
                    data = conn.recv(64)
                    if data:
                        seen.append(data)
                except OSError:
                    pass
                conn.sendall(b"OK")
                conn.close()
            except OSError:
                break

    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1], seen


def _start_mock_http_proxy(*, expected_auth: str = "") -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def handle(conn: socket.socket) -> None:
        try:
            raw = b""
            while b"\r\n\r\n" not in raw:
                chunk = conn.recv(1024)
                if not chunk:
                    return
                raw += chunk
            head = raw.decode("latin-1")
            if expected_auth:
                expected_hdr = f"Proxy-Authorization: Basic {base64.b64encode(expected_auth.encode()).decode()}"
                if expected_hdr not in head:
                    conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                    return
            first_line = head.splitlines()[0]
            target = first_line.split(" ")[1]
            t_host, _, t_port_s = target.rpartition(":")
            upstream = socket.create_connection((t_host, int(t_port_s)), timeout=3.0)
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            def pipe(src: socket.socket, dst: socket.socket) -> None:
                try:
                    while True:
                        buf = src.recv(4096)
                        if not buf:
                            break
                        dst.sendall(buf)
                except OSError:
                    pass
                finally:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            t1 = threading.Thread(target=pipe, args=(conn, upstream), daemon=True)
            t2 = threading.Thread(target=pipe, args=(upstream, conn), daemon=True)
            t1.start()
            t2.start()
            t1.join(timeout=3.0)
            t2.join(timeout=3.0)
            upstream.close()
        except OSError:
            pass
        finally:
            conn.close()

    def loop() -> None:
        while True:
            try:
                conn, _ = srv.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except OSError:
                break

    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1]


def _start_mock_socks5_proxy(*, expected_user: str = "", expected_pass: str = "") -> tuple[socket.socket, int, list[int]]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    atyp_seen: list[int] = []

    def handle(conn: socket.socket) -> None:
        try:
            greet = conn.recv(16)
            if len(greet) < 3 or greet[0] != 5:
                return
            methods = greet[2 : 2 + greet[1]]
            need_auth = bool(expected_user or expected_pass)
            if need_auth:
                if 2 not in methods:
                    conn.sendall(b"\x05\xff")
                    return
                conn.sendall(b"\x05\x02")
                ver = conn.recv(1)
                if ver != b"\x01":
                    return
                ulen = conn.recv(1)[0]
                u = conn.recv(ulen).decode("utf-8")
                plen = conn.recv(1)[0]
                p = conn.recv(plen).decode("utf-8")
                if u != expected_user or p != expected_pass:
                    conn.sendall(b"\x01\x01")
                    return
                conn.sendall(b"\x01\x00")
            else:
                conn.sendall(b"\x05\x00")

            req = conn.recv(4)
            atyp = req[3]
            atyp_seen.append(atyp)
            if atyp == 1:
                host = socket.inet_ntoa(conn.recv(4))
            elif atyp == 3:
                dlen = conn.recv(1)[0]
                host = conn.recv(dlen).decode("utf-8")
            else:
                conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            port = int.from_bytes(conn.recv(2), "big")
            upstream = socket.create_connection((host, port), timeout=3.0)
            conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")

            def pipe(src: socket.socket, dst: socket.socket) -> None:
                try:
                    while True:
                        buf = src.recv(4096)
                        if not buf:
                            break
                        dst.sendall(buf)
                except OSError:
                    pass

            t1 = threading.Thread(target=pipe, args=(conn, upstream), daemon=True)
            t2 = threading.Thread(target=pipe, args=(upstream, conn), daemon=True)
            t1.start()
            t2.start()
            t1.join(timeout=3.0)
            t2.join(timeout=3.0)
            upstream.close()
        except OSError:
            pass
        finally:
            conn.close()

    def loop() -> None:
        while True:
            try:
                conn, _ = srv.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except OSError:
                break

    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1], atyp_seen


class ProxySystemTests(unittest.TestCase):
    def test_defaults_to_none_and_migrates_fake_1080(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            with patch("app.paths.user_data_dir", return_value=data_dir):
                fresh = px.load()
                self.assertEqual(fresh.mode, px.PROXY_MODE_NONE)
                self.assertFalse(fresh.enabled)
                self.assertEqual(fresh.url, "")
                self.assertEqual(fresh.host, "")

                # Legacy disabled file containing hardcoded 127.0.0.1:1080 migrates to clean none
                (data_dir / "proxy.json").write_text(
                    json.dumps({"enabled": False, "url": "socks5://127.0.0.1:1080"}),
                    encoding="utf-8",
                )
                migrated = px.load()
                self.assertEqual(migrated.mode, px.PROXY_MODE_NONE)
                self.assertFalse(migrated.enabled)
                self.assertEqual(migrated.url, "")

    def test_dummy_open_port_rejected_by_verify_proxy_candidate(self) -> None:
        dummy, port = _start_dummy_port()
        try:
            cand = px.DetectedProxyCandidate(
                source="test",
                url=f"socks5h://127.0.0.1:{port}",
                scheme="socks5h",
                host="127.0.0.1",
                port=port,
            )
            checked = px.verify_proxy_candidate(cand, test_host="127.0.0.1", test_port=port, timeout=1.5)
            self.assertFalse(checked.working)
        finally:
            dummy.close()

    def test_http_connect_proxy_auth_and_no_silent_direct_fallback(self) -> None:
        target, t_port, seen = _start_mock_target()
        proxy_srv, p_port = _start_mock_http_proxy(expected_auth="alice:pw123")
        try:
            bad = px.ProxySettings(
                mode=px.PROXY_MODE_MANUAL,
                scheme="http",
                host="127.0.0.1",
                port=p_port,
                username="alice",
                password="wrong",
                hosts=[f"127.0.0.1:{t_port}"],
            )
            with self.assertRaises(px.ProxyError):
                px.connect(bad, "127.0.0.1", t_port, timeout=2.0)
            self.assertEqual(seen, [])  # MUST NOT fall back silently to direct!

            good = px.ProxySettings(
                mode=px.PROXY_MODE_MANUAL,
                scheme="http",
                host="127.0.0.1",
                port=p_port,
                username="alice",
                password="pw123",
                hosts=[f"127.0.0.1:{t_port}"],
            )
            with px.connect(good, "127.0.0.1", t_port, timeout=2.0) as sock:
                sock.sendall(b"hi")
                self.assertEqual(sock.recv(2), b"OK")
            self.assertEqual(seen, [b"hi"])
        finally:
            proxy_srv.close()
            target.close()

    def test_socks5_and_socks5h_auth_and_remote_dns(self) -> None:
        target, t_port, seen = _start_mock_target()
        proxy_srv, p_port, atyp_seen = _start_mock_socks5_proxy(expected_user="bob", expected_pass="sec777")
        try:
            cfg = px.ProxySettings(
                mode=px.PROXY_MODE_MANUAL,
                scheme="socks5h",
                host="127.0.0.1",
                port=p_port,
                username="bob",
                password="sec777",
                hosts=[f"localhost:{t_port}"],
            )
            with px.connect(cfg, "localhost", t_port, timeout=2.0) as sock:
                sock.sendall(b"s5h")
                self.assertEqual(sock.recv(2), b"OK")
            self.assertIn(3, atyp_seen)  # DOMAINNAME ATYP=3 confirms remote DNS for socks5h
            self.assertEqual(seen, [b"s5h"])
        finally:
            proxy_srv.close()
            target.close()

    def test_env_detection_and_ngrok_socks5_honest_warning(self) -> None:
        with patch.dict("os.environ", {"HTTPS_PROXY": "http://127.0.0.1:8888", "NO_PROXY": ""}, clear=False):
            det = px.detect_system_proxies()
            self.assertTrue(any(c.port == 8888 and c.scheme == "http" for c in det.candidates))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("app.core.service_manager.user_data_dir", return_value=root), patch(
                "app.paths.user_data_dir", return_value=root
            ):
                mgr = ServiceManager(Settings(active_provider=PROVIDER_NGROK))
                mgr.connections.configure_provider(
                    PROVIDER_NGROK,
                    {"reserved_domain": "demo.ngrok.app"},
                    secrets={"authtoken": "ng-tok-123"},
                )
                logged: list[str] = []
                mgr.log_line.connect(lambda _src, line: logged.append(line))

                socks_proxy = px.ProxySettings(
                    mode=px.PROXY_MODE_MANUAL,
                    scheme="socks5h",
                    host="127.0.0.1",
                    port=1080,
                )
                with patch("app.core.proxy.load", return_value=socks_proxy), patch(
                    "pathlib.Path.is_file", return_value=True
                ), patch(
                    "app.core.tunnels.ngrok._candidate_ngrok_paths", return_value=[Path("C:/mock/ngrok.exe")]
                ), patch(
                    "app.core.tunnels.ngrok.run_cli_capture", return_value=(0, "ngrok version 3.18.0", "")
                ), patch.object(mgr.tunnel, "start") as start_mock:
                    mgr._start_tunnel()
                    self.assertTrue(any("SOCKS5" in ln for ln in logged))
                    _prog, _args = start_mock.call_args[0]
                    env_socks = start_mock.call_args[1]["env"]
                    self.assertNotIn("HTTPS_PROXY", env_socks)

                http_proxy = px.ProxySettings(
                    mode=px.PROXY_MODE_MANUAL,
                    scheme="http",
                    host="127.0.0.1",
                    port=8080,
                )
                with patch("app.core.proxy.load", return_value=http_proxy), patch(
                    "pathlib.Path.is_file", return_value=True
                ), patch(
                    "app.core.tunnels.ngrok._candidate_ngrok_paths", return_value=[Path("C:/mock/ngrok.exe")]
                ), patch(
                    "app.core.tunnels.ngrok.run_cli_capture", return_value=(0, "ngrok version 3.18.0", "")
                ), patch.object(mgr.tunnel, "start") as start_mock:
                    mgr._start_tunnel()
                    env_http = start_mock.call_args[1]["env"]
                    self.assertEqual(env_http.get("HTTPS_PROXY"), "http://127.0.0.1:8080")
                    self.assertEqual(env_http.get("HTTP_PROXY"), "http://127.0.0.1:8080")


if __name__ == "__main__":
    unittest.main()
