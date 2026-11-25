# MCP-app v1.0.0 Transport & Client Compatibility Matrix

Statuses are strictly evidence-based:
- **VERIFIED**: Observed end-to-end in automated integration/E2E tests or local smoke runs on this repository.
- **NOT_APPLICABLE**: Protocol or product combination does not apply by design.
- **BLOCKED**: Implemented and unit/mock-tested, but live verification requires external accounts, domains, paid plans, or third-party desktop/cloud clients unavailable in the build environment.

## 1. Transports (4 UI Providers + Internal Loopback Test Mode)

| Transport | Status | SSE Streaming | Public URL | Evidence / Notes |
|---|---|---|---|---|
| `cloudflare_quick` | **VERIFIED** *(local client/binary)* | No (JSON-only forced) | Ephemeral `*.trycloudflare.com` | Built-in signed `cloudflared 2026.11.2` verified (`--selftest`); proxy v2 (`none`/`auto`/`manual`) & diagnostics verified; live external AI SaaS roundtrip **BLOCKED** |
| `cloudflare_named` | **BLOCKED** *(live domain)* | Yes | Custom HTTPS domain | Supports automatic API Token wizard + existing Cloudflare Tunnel Token mode; domain/token persistence across provider switches & restarts verified in unit tests; live test blocked without owner domain/token |
| `ngrok` | **BLOCKED** *(live account)* | Yes | ngrok HTTPS URL | Agent v3 integration, SecretStore `NGROK_AUTHTOKEN`, `HTTP_PROXY`/`HTTPS_PROXY` support (honest SOCKS5 warning), `/api/endpoints`, and live issuer sync unit-tested; live smoke blocked without ngrok account |
| `tailscale_funnel` | **BLOCKED** *(Tailnet/Funnel ACL)* | Yes | `https://<node>.ts.net` | CLI `status --json` / `funnel status --json` / ownership guard, non-destructive `off`, and direct OS daemon routing (bypassing MCP-app proxy bridge) unit-tested; live publication blocked pending owner Tailnet/Funnel ACL |
| *(Internal headless loopback)* | **VERIFIED** | Yes | No (`127.0.0.1`) | Removed from selectable UI providers (legacy `local_only` migrates safely to `PROVIDER_NONE`); verified end-to-end for headless/backend OAuth & Playwright multi-browser E2E |

## 2. OAuth 2.1 Browser Flow (Chromium / Chrome / Edge / Firefox)

| Browser Engine | Status | Notes |
|---|---|---|
| **Playwright Chromium** | **VERIFIED** | Full DCR -> `/authorize` -> `/oauth/consent` -> bad token 403 retry -> valid token -> 303 cross-origin callback (no CSP `form-action` block) -> `/token` PKCE -> `tools/list` (`tests/e2e/test_oauth_browsers_playwright.py`) |
| **Google Chrome** | **VERIFIED** | Tested live via Playwright `channel="chrome"` on Windows 11 (`test_oauth_browsers_playwright.py`) |
| **Microsoft Edge** | **VERIFIED** | Tested live via Playwright `channel="msedge"` on Windows 11 (`test_oauth_browsers_playwright.py`) |
| **Mozilla Firefox** | **VERIFIED** | Tested live via Playwright `firefox` (`test_oauth_browsers_playwright.py`) |

## 3. MCP Clients & Integrations

| Client / Target | Compatible Transports | Status | Notes |
|---|---|---|---|
| **MCP Inspector / Python MCP SDK** | Local, CF Quick/Named, ngrok, Tailscale | **VERIFIED** | Verified locally via `mcp` SDK HTTP client (`test_connection_transports.py`, `test_mcp_gateway.py`, `test_acceptance_oauth_and_desktop.py`) |
| **ChatGPT / Codex / OpenAI API** | Public OAuth HTTPS (`CF Quick/Named`, `ngrok`, `Tailscale`) | **BLOCKED** | Requires owner external AI SaaS account and live public HTTPS endpoint |
| **Claude / Gemini / Notion / VS Code** | Public OAuth HTTPS (`CF Quick/Named`, `ngrok`, `Tailscale`) | **BLOCKED** *(external cloud clients)* | Cloud connectors require owner external accounts; OpenAI Secure MCP Tunnel was removed from v1.0.0 |
| **SolidWorks MCP (Gateway Upstream)** | Stdio (User Session COM via Gateway) | **BLOCKED** *(live COM creation)* | Template & profile (`solidworks_mcp_template`) shipped; `SLDWORKS.exe` COM automation requires owner interactive session & SolidWorks license |
