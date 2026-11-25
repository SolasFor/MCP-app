# MCP Gateway (`v0.9.2`)

MCP-app acts simultaneously as a downstream MCP OAuth 2.1 Server (serving remote AI clients) and an upstream **MCP Gateway** aggregating local `stdio` processes and remote `Streamable HTTP` / legacy `SSE` MCP servers.

## Architecture & Module Layout

- [`backend/gateway/models.py`](file:///d:/Coding/MCP%20App/backend/gateway/models.py) — `UpstreamServerProfile`, `UpstreamToolEntry`, `GatewayServerStatus`, validation rules.
- [`backend/gateway/security.py`](file:///d:/Coding/MCP%20App/backend/gateway/security.py) — deterministic collision-free `<server_id>__<tool>` namespaces (≤ 64 chars), SSRF / cloud-metadata / self-recursion guards (`validate_upstream_url`), hop/loop prevention (`X-MCP-Gateway-Id`, `X-MCP-Gateway-Hop`), downstream header stripping, untrusted launcher detection, and description sanitization.
- [`backend/gateway/store.py`](file:///d:/Coding/MCP%20App/backend/gateway/store.py) — persistent config store in JSON with sensitive env vars, bearer tokens, and headers isolated into DPAPI `SecretStore` (`secret://...` refs). Includes `preview_standard_mcp_json` / `commit_import` (owner-approval gated), `export_redacted_json`, and `solidworks_mcp_template`.
- [`backend/gateway/upstream_client.py`](file:///d:/Coding/MCP%20App/backend/gateway/upstream_client.py) — `mcp` SDK client sessions for `stdio`, `streamable_http`, and `sse`, bounded pagination, strict deadlines without automatic retries on non-idempotent tool calls, and `notifications/tools/list_changed` handling.
- [`backend/gateway/router.py`](file:///d:/Coding/MCP%20App/backend/gateway/router.py) — fault-isolated discovery, fail-closed per-client OAuth profile checks (`safe` / `allowlist` / `full`), `per_client` vs `shared_service` session isolation, multimodal `TextContent`/`ImageContent`/`structuredContent` size caps & secret redaction.
- [`app/ui/pages/gateway_page.py`](file:///d:/Coding/MCP%20App/app/ui/pages/gateway_page.py) — Linear + Docker Desktop Gateway management view (`Add`, `SolidWorks Preset`, `Import JSON`, `Export (Redacted)`, `Refresh & Test`, tool schema inspector, redacted logs).

## Security Guarantees & Boundaries

1. **Fail-Closed Per-Client Authorization**: Upstream gateway tools are hidden from `tools/list` and denied with JSON-RPC `-32602` on `tools/call` unless the client is owner-approved, not emergency-stopped, meets `min_profile`, is allowed in `allowed_clients` (when set), and the tool passes `allowed_tools` / `denied_tools`.
2. **Credential Isolation**: Downstream OAuth Bearer tokens and cookies are never forwarded upstream. Upstream credentials remain inside `SecretStore` and are redacted from gateway logs, errors, exported JSON, text blocks, and `structuredContent`.
3. **SSRF & Loop Prevention**: Upstream URLs block cloud metadata IPs/hostnames (`169.254.169.254`, `metadata.google.internal`), plain HTTP on non-loopback hosts, embedded URL credentials, and self-recursion. `HybridAuthMiddleware` rejects self-looped requests with HTTP `400 gateway_loop_detected`.
4. **Safe Import**: Standard `mcpServers` JSON configurations (Claude/Cursor/VS Code) are imported disabled/unapproved until the owner reviews launcher warnings (`npx`/`uvx`/encoded scripts) and confirms import. Inline secret env variables are moved into encrypted `SecretStore` refs.

## SolidWorks MCP Setup (Windows User Session COM)

MCP-app provides a preconfigured **SolidWorks Preset** (`solidworks_mcp_template()`) defaulting to `enabled=False`, `approved_by_owner=False`, `session_isolation="shared_service"`, and `min_profile="allowlist"`.

Requirements for local live SolidWorks CAD automation:
1. Licensed local SolidWorks installation on Windows (`SLDWORKS.exe` running inside the **same interactive Windows user session** as MCP-app so COM `win32com`/`pythoncom` automation is reachable).
2. A compatible local `stdio` SolidWorks MCP package (default command: `python -m solidworks_mcp`) reviewed and explicitly approved by the owner in **Gateway → SolidWorks Preset**.
3. Never target active production assemblies during smoke tests; create test `.SLDPRT` files in an isolated scratch directory.

> **Current Verification Status (v0.9.2)**:
> - Automated `stdio` + `Streamable HTTP` + `SSE` + failing-server fault isolation + OAuth permission isolation + `GatewayPage` GUI tests pass locally and in CI.
> - Live SolidWorks COM CAD smoke test is marked **`BLOCKED`** on build/dev machines without a local `SLDWORKS.exe` installation and license.
> - External end-to-end **ChatGPT / MCP Inspector → Tunnel → Gateway** live smoke depends on owner tunnel credentials / remote client verification (`BLOCKED` in offline CI).
