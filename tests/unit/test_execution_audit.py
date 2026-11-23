"""Regression tests for post-SDK OAuth warnings and privacy-safe execution audit."""
from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.execution_audit import ExecutionAudit, classify_command_output


class ExecutionAuditTests(unittest.TestCase):
    def test_records_client_profile_outcome_but_never_command_or_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "server" / "mcp_execution_audit.jsonl"
            with ExecutionAudit(path) as audit:
                secret_command = "powershell -Command Write-Host SECRET_EXECUTION_ARGUMENT_7284"
                secret_host = "confidential-ssh-host.example"
                action = "a1b2c3d4e5f60708"
                audit.record(
                    client_id="notion-registered-client", kind="ssh", profile="full",
                    event="started", command=secret_command, host=secret_host,
                    port=2222, action_id=action,
                )
                audit.record(
                    client_id="notion-registered-client", kind="ssh", profile="full",
                    event="completed", command=secret_command, host=secret_host,
                    port=2222, action_id=action, exit_code=0, duration_ms=351,
                )
                raw = path.read_text(encoding="utf-8")
                self.assertNotIn("SECRET_EXECUTION_ARGUMENT_7284", raw)
                self.assertNotIn("confidential-ssh-host.example", raw)
                self.assertNotIn("powershell", raw)
                self.assertNotIn("stdout", raw)
                lines = [json.loads(line) for line in raw.splitlines()]
                self.assertEqual([record["event"] for record in lines], ["started", "completed"])
                self.assertEqual(lines[0]["action_id"], lines[1]["action_id"])
                self.assertEqual(lines[1]["client_id"], "notion-registered-client")
                self.assertEqual(lines[1]["duration_ms"], 351)
                self.assertEqual(lines[1]["exit_code"], 0)
                self.assertEqual(
                    lines[0]["command_sha256"],
                    hashlib.sha256(secret_command.encode()).hexdigest(),
                )

    def test_result_classification_not_based_on_command_text(self):
        self.assertEqual(classify_command_output("Exit code: 0\nSTDOUT:\nhello"), ("completed", 0))
        self.assertEqual(classify_command_output("Exit code: 3\nSTDOUT:\n"), ("failed", 3))
        self.assertEqual(classify_command_output("❌ command timed out"), ("failed", None))

    def test_reject_invalid_audit_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            with ExecutionAudit(Path(tmp) / "audit.jsonl") as audit:
                with self.assertRaises(ValueError):
                    audit.record(
                        client_id="client", kind="ssh", profile="safe",
                        event="started", command="echo", action_id="bad-token",
                    )


class HybridAuthMiddlewareTests(unittest.TestCase):
    @staticmethod
    async def send_response(status: int, authorization: str = "Bearer valid-oauth-access"):
        from backend.server import HybridAuthMiddleware, MCP_PATH
        sent = []
        async def application(scope, receive, send):
            await send({"type": "http.response.start", "status": status, "headers": []})
            await send({"type": "http.response.body", "body": b"ok", "more_body": False})
        scope = {
            "type": "http", "path": MCP_PATH, "method": "POST",
            "headers": [(b"authorization", authorization.encode("ascii"))],
            "client": ("127.0.0.1", 12345), "query_string": b"",
        }
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}
        async def send(message):
            sent.append(message)
        await HybridAuthMiddleware(application)(scope, receive, send)
        return sent

    def test_oauth_bearer_does_not_generate_false_warning_after_http_200(self):
        from backend import server
        with patch.object(server.logger, "warning") as warnings:
            result = asyncio.run(self.send_response(200))
        warnings.assert_not_called()
        self.assertEqual(result[0]["status"], 200)

    def test_oauth_bearer_actual_401_generates_warning_without_token(self):
        from backend import server
        with patch.object(server.logger, "warning") as warnings:
            result = asyncio.run(self.send_response(401, "Bearer SECRET_NOT_VALID"))
        self.assertEqual(result[0]["status"], 401)
        self.assertEqual(warnings.call_count, 1)
        call = str(warnings.call_args)
        self.assertIn("401", call)
        self.assertNotIn("SECRET_NOT_VALID", call)


if __name__ == "__main__":
    unittest.main()
