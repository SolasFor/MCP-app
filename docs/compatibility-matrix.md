# MCP-app v1.0.0 Transport & Client Compatibility Matrix

Statuses are strictly evidence-based:
- **VERIFIED**: Observed end-to-end in automated integration tests or local smoke runs on this repository.
- **NOT_APPLICABLE**: Protocol or product combination does not apply by design.
- **BLOCKED**: Implemented and unit/mock-tested, but live verification requires external accounts, domains, paid plans, or third-party desktop/cloud clients unavailable in the build environment.

## 1. Transports (5 Supported Modes)

| Transport | Status | SSE Streaming | Public URL | Evidence / Notes |
|---|---|---|---|---|
| `local_only` | **VERIFIED** | Yes | No (`127.0.0.1`) | Live OAuth DCR/PKCE + MCP `initialize`/`tools/list`/`tools/call` + restart & owner-token-rotation reconnect persistence (`test_connection_transports.py`, `test_acceptance_oauth_and_desktop.py`) |
| `cloudflare_quick` | **VERIFIED** *(local client/binary)* | No (JSON-only forced) | Ephemeral `*.trycloudflare.com` | Built-in signed `cloudflared 2026.11.2` verified (`--selftest`); SSE disabled safely for Quick Tunnel (`test_tunnel_log.py`, `test_transport_config.py`); live external AI SaaS roundtrip **BLOCKED** (no cloud AI SaaS credentials in CI) |
| `cloudflare_named` | **BLOCKED** *(live domain)* | Yes | Custom HTTPS domain | Domain wizard, `cloudflared.json` Authenticode/SHA-256, DNS/CORS/OAuth isolation unit/mock-tested; live test blocked without owner Cloudflare API token & domain |
| `ngrok` | **BLOCKED** *(live account)* | Yes | ngrok HTTPS URL | Agent v3 integration, SecretStore `NGROK_AUTHTOKEN`, `/api/endpoints`, `ERR_NGROK_*` log parser, and live issuer/resource URL sync unit-tested; live smoke blocked (`ngrok` authtoken/account absent) |
| `tailscale_funnel` | **BLOCKED** *(Tailnet/Funnel ACL)* | Yes | `https://<node>.ts.net` | CLI `status --json` / `funnel status --json` / ownership guard, non-destructive `off`, and issuer/resource URL sync unit-tested; live publication blocked pending owner Tailnet/Funnel ACL approval |

## 2. MCP Clients & Integrations

| Client / Target | Compatible Transports | Status | Notes |
|---|---|---|---|
| **MCP Inspector / Python MCP SDK** | Local, CF Quick/Named, ngrok, Tailscale | **VERIFIED** | Verified locally via `mcp` SDK HTTP client (`test_connection_transports.py`, `test_mcp_gateway.py`, `test_acceptance_oauth_and_desktop.py`) |
| **ChatGPT / Codex / OpenAI API** | Public OAuth HTTPS (`CF Quick/Named`, `ngrok`, `Tailscale`) | **BLOCKED** | Requires owner external AI SaaS account and live public HTTPS endpoint |
| **Claude / Gemini / Notion / VS Code** | Public OAuth HTTPS (`CF Quick/Named`, `ngrok`, `Tailscale`), Local (`127.0.0.1` for desktop IDEs) | **BLOCKED** *(external cloud clients)* | Cloud connectors require owner external accounts; OpenAI Secure MCP Tunnel was removed from v1.0.0 |
| **SolidWorks MCP (Gateway Upstream)** | Stdio (User Session COM via Gateway) | **BLOCKED** *(live COM creation)* | Template & profile (`solidworks_mcp_template`) shipped; `SLDWORKS.exe` COM automation requires owner interactive session & valid SolidWorks license test |
