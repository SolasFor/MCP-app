# MCP-app v1.0.0 Transport & Client Compatibility Matrix

Statuses are strictly evidence-based:
- **VERIFIED**: Observed end-to-end in automated integration tests or local smoke runs on this repository.
- **NOT_APPLICABLE**: Protocol or product combination does not apply by design.
- **BLOCKED**: Implemented and unit/mock-tested, but live verification requires external accounts, domains, paid plans, or third-party desktop/cloud clients unavailable in the build environment.

## 1. Transports (6 Supported Modes)

| Transport | Status | SSE Streaming | Public URL | Evidence / Notes |
|---|---|---|---|---|
| `local_only` | **VERIFIED** | Yes | No (`127.0.0.1`) | Live OAuth DCR/PKCE + MCP `initialize`/`tools/list`/`tools/call` + restart persistence (`test_connection_transports.py`), frozen `--headless` `/health` smoke |
| `cloudflare_quick` | **VERIFIED** *(local client/binary)* | No (JSON-only forced) | Ephemeral `*.trycloudflare.com` | Built-in signed `cloudflared 2026.11.2` verified (`--selftest`); SSE disabled safely for Quick Tunnel (`test_tunnel_log.py`, `test_transport_config.py`); live external AI SaaS roundtrip **BLOCKED** (no cloud AI SaaS credentials in CI) |
| `cloudflare_named` | **BLOCKED** *(live domain)* | Yes | Custom HTTPS domain | Domain wizard, `cloudflared.json` Authenticode/SHA-256, DNS/CORS/OAuth isolation unit/mock-tested; live test blocked without owner Cloudflare API token & domain |
| `ngrok` | **BLOCKED** *(live account)* | Yes | ngrok HTTPS URL | Agent v3 integration, SecretStore `NGROK_AUTHTOKEN`, `/api/endpoints`, `ERR_NGROK_*` log parser unit-tested; live smoke blocked (`ngrok` CLI & authtoken absent) |
| `tailscale_funnel` | **BLOCKED** *(Tailnet/Funnel ACL)* | Yes | `https://<node>.ts.net` | CLI `status --json` / `funnel status --json` / ownership guard & non-destructive `off` unit-tested (`tailscale 1.104.2` detected); live publication blocked pending owner Tailnet/Funnel ACL approval |
| `openai_tunnel` | **BLOCKED** *(OpenAI entitlement)* | Provider-dependent | Non-public (`tunnel_id` only) | Marked `is_public_url=False`; never claims universal plan support; local OAuth/Bearer remains mandatory; live smoke blocked (`openai/tunnel-client` & OpenAI key absent) |

## 2. MCP Clients & Integrations

| Client / Target | Compatible Transports | Status | Notes |
|---|---|---|---|
| **MCP Inspector / Python MCP SDK** | Local, CF Quick/Named, ngrok, Tailscale | **VERIFIED** | Verified locally via `mcp` SDK HTTP client (`test_connection_transports.py`, `test_mcp_gateway.py`) |
| **ChatGPT / Codex / OpenAI API** | OpenAI Secure Tunnel *(supported tiers only)*, Public OAuth HTTPS | **BLOCKED** | Requires owner OpenAI account/tier entitlement and live external tunnel |
| **Claude / Gemini / Notion / VS Code** | Public OAuth HTTPS (`CF Quick/Named`, `ngrok`, `Tailscale`), Local (`127.0.0.1` for desktop IDEs) | **BLOCKED** *(external cloud clients)* / **NOT_APPLICABLE** *(OpenAI Tunnel)* | OpenAI Secure Tunnel is **NOT_APPLICABLE** to third-party non-OpenAI clients; cloud connectors require owner external accounts |
| **SolidWorks MCP (Gateway Upstream)** | Stdio (User Session COM via Gateway) | **BLOCKED** *(live COM creation)* | Template & profile (`solidworks_mcp_template`) shipped; `SLDWORKS.exe` COM automation requires owner interactive session & valid SolidWorks license test |
