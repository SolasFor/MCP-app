"""Real local HTTP server fixture for Stage 6 Server Manager tests."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def _emit(line: str, *, err: bool = False) -> None:
    stream = sys.stderr if err else sys.stdout
    stream.write(line + "\n")
    stream.flush()


class _Handler(BaseHTTPRequestHandler):
    health_path = "/health"
    healthy = True
    secret_env_name = ""

    def do_GET(self) -> None:  # noqa: N802
        if self.path == self.health_path:
            code = 200 if self.healthy else 503
            body = json.dumps({"ok": self.healthy}).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            _emit(f"GET {self.path} -> {code}")
            return
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--health-path", default="/health")
    parser.add_argument("--unhealthy", action="store_true")
    parser.add_argument("--secret-env", default="")
    parser.add_argument("--crash-after", type=float, default=0.0)
    parser.add_argument("--exit-code", type=int, default=1)
    parser.add_argument("--spawn-child", action="store_true")
    parser.add_argument("--child-pid-file", default="")
    parser.add_argument("--pid-file", default="")
    args = parser.parse_args()

    _Handler.health_path = args.health_path
    _Handler.healthy = not args.unhealthy

    if args.pid_file:
        Path(args.pid_file).write_text(str(os.getpid()), encoding="utf-8")

    child = None
    if args.spawn_child:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if args.child_pid_file:
            Path(args.child_pid_file).write_text(str(child.pid), encoding="utf-8")

    if args.secret_env:
        val = os.environ.get(args.secret_env, "")
        _emit(f"BOOT {args.secret_env}={val}")
        _emit(f"ERRBOOT {args.secret_env}={val}", err=True)
    else:
        _emit("BOOT ready")

    httpd = ThreadingHTTPServer((args.host, args.port), _Handler)

    def stop_later() -> None:
        time.sleep(args.crash_after)
        _emit("crashing now", err=True)
        os._exit(args.exit_code)

    if args.crash_after > 0:
        threading.Thread(target=stop_later, daemon=True).start()

    try:
        httpd.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        if child is not None and child.poll() is None:
            child.terminate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
