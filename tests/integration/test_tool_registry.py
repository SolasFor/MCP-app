"""Integration-level profile registration checks using the installed MCP SDK."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = """
import asyncio
import json
from backend.server import mcp, server_info
async def main():
    tools = sorted(t.name for t in await mcp.list_tools())
    resources = sorted(str(r.uri) for r in await mcp.list_resources())
    print(json.dumps({"tools": tools, "resources": resources, "info": server_info()}))
asyncio.run(main())
"""


def registry(*, advanced: bool = False, execute: bool = False, hosts: str = "", executables: str = "") -> dict:
    env = os.environ.copy()
    env.update({
        "MCP_PUBLIC_URL": "https://mcp-ci.example.com/mcp",
        "MCP_SECRET_TOKEN": "test-only-not-a-real-token",
        "MCP_ALLOW_QUERY_TOKEN": "0",
        "MCP_JSON_RESPONSE": "1",
        "MCP_ENABLE_ADVANCED": "1" if advanced else "0",
        "MCP_ENABLE_EXECUTION": "1" if execute else "0",
        "MCP_ALLOWED_HOSTS": hosts,
        "MCP_ALLOWED_EXECUTABLES": executables,
    })
    proc = subprocess.run(
        [sys.executable, "-c", SCRIPT],
        cwd=ROOT, env=env, text=True, capture_output=True,
        timeout=20, check=True,
    )
    return json.loads(proc.stdout.strip().splitlines()[-1])


class ToolRegistryTests(unittest.TestCase):
    def test_public_profile_is_only_safe_server_info(self) -> None:
        result = registry()
        self.assertEqual(result["tools"], ["server_info"])
        self.assertEqual(result["resources"], [])
        self.assertNotIn("test-only-not-a-real-token", result["info"])

    def test_execution_flag_cannot_bypass_advanced_flag(self) -> None:
        result = registry(execute=True, hosts="example.com", executables="python")
        self.assertEqual(result["tools"], ["server_info"])

    def test_advanced_files_do_not_enable_remote_execution(self) -> None:
        result = registry(advanced=True)
        self.assertEqual(
            result["tools"],
            ["read_workspace_file", "server_info", "write_workspace_file"],
        )
        self.assertIn("system://environment", result["resources"])

    def test_both_opt_ins_still_require_exact_allowlists(self) -> None:
        result = registry(advanced=True, execute=True)
        self.assertNotIn("run_local_command", result["tools"])
        self.assertNotIn("run_ssh_command", result["tools"])

    def test_execution_requires_both_flags_and_allowlists(self) -> None:
        result = registry(advanced=True, execute=True, hosts="host.example", executables=Path(sys.executable).name)
        self.assertIn("run_local_command", result["tools"])
        self.assertIn("run_ssh_command", result["tools"])


if __name__ == "__main__":
    unittest.main()
