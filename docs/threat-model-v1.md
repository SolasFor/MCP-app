# MCP-app v1.0.0 Threat Model & Security Review

This document summarizes the security architecture, trust boundaries, verified mitigations, and explicit non-guarantees of **MCP-app v1.0.0**.

## 1. Trust Boundaries

1. **External MCP Clients & Public Tunnels** (`Cloudflare Quick/Named`, `ngrok`, `Tailscale Funnel`, `Local only`):
   - Untrusted external requests arrive over TLS tunnels forwarding to `127.0.0.1:<port>`.
   - `HybridAuthMiddleware` strips legacy `?token=` from URLs (never logging tokens) and enforces DNS-rebinding allowlists (`TransportSecuritySettings`) plus Gateway loop header defense (`check_loop_headers`).
   - Authentication is **never** disabled based on loopback source IP or tunnel trust; OAuth bearer tokens (`LocalConsentOAuthProvider`) validate `issuer`, `resource`, expiry, and live approval.
   - Rotating the owner token revokes all issued OAuth access/refresh tokens and resets `clients.approved_at` while keeping DCR `client_id` entries so authorized clients can reconnect and re-consent cleanly with the new owner token.
   - `issuer` transitions across incompatible providers prompt the owner before switching and never reuse tokens across issuers.

2. **Three OAuth Execution Profiles (`safe`, `allowlist`, `full`)**:
   - **`safe`**: Fail-closed fallback for unapproved clients, corrupted encrypted policies, invalid configuration values, and active Emergency Stop; exposes only read-only `server_info`.
   - **`allowlist`** *(default scenario on first launch)*: Grants exact-command Windows execution (`ExecutionApprovals`, non-shell built-ins for `dir`/`ls`/`pwd`/`echo`), exact SSH host/command allowlists, and Workspaces/Git/Servers/Tasks/Extensions/Remote tools gated by per-client policies and permissions.
   - **`full`**: Enables arbitrary Windows `cmd.exe` / PowerShell / SSH commands and `oauth_managed_server` / `extension_enable` / `extension_disable` without per-call confirmations inside MCP-app.
   - **CRITICAL NON-GUARANTEE**: **Full access is NOT an OS sandbox.** Arbitrary code executed under `full` runs with the full privileges of the signed-in Windows user (including access to user files and DPAPI-protected data). Do not enable `full` for untrusted clients.
   - Emergency Stop (`runtime_control` in SQLite + `DesktopPolicyStore`) immediately blocks all non-`server_info` OAuth discovery and live/queued execution fail-closed.

3. **Third-Party MCP Gateway Upstreams & Extensions (`v0.9.2`, `v0.9.7`)**:
   - Gateway enforces loop guards, SecretStore-isolated env/headers, `session_isolation`, and per-client authorization.
   - Extensions run out-of-process over JSON-RPC (`--run-extension`), verified by **Ed25519 signature** or owner-pinned **SHA-256** (`allow_unsigned_sha256` explicit confirmation).
   - **CRITICAL NON-GUARANTEE**: Running an extension or upstream MCP server in a separate child process isolates core crashes and strips unrelated environment secrets (`sanitize_child_env`), **not** untrusted OS code execution under the user account. Only install extensions from trusted sources.

4. **Computer Use (`v0.9.6`) & Windows Session 0**:
   - Disabled by default; requires explicit owner opt-in (`DesktopPolicy.enabled`).
   - Fails closed on locked sessions, UAC/secure desktops (`OpenInputDesktop`), and elevated target windows (UIPI).
   - Password fields / sensitive inputs are blocked unless explicitly opted in; screenshots stay in memory only (`ImageContent`, never written to disk by default).
   - If running `--headless` as a Session 0 service, interactive Computer Use requires a separate interactive user-session desktop agent.

5. **Remote SSH / SFTP (`v0.9.8`)**:
   - Strictly enforces `paramiko.RejectPolicy()` against explicit `known_hosts` files; changed host keys are immediately rejected (`PermissionError`).
   - SFTP enforces canonical root allowlists, server-side `sftp.normalize` symlink escape checks, and byte quotas.
   - Restricted profiles forbid shell metacharacters and never invoke `sudo` automatically.

6. **Monitoring, Backup & Local Admin REST API (`v0.9.9`)**:
   - Admin REST endpoints (`/api/v1/*`) are strictly separated from `/mcp` and reject non-loopback `Host` headers, non-loopback client IPs, and tunnel forwarding headers (`Cf-Ray`, `X-Forwarded-*`, `Ngrok-Trace-Id`, `Tailscale-User-Login`).
   - Config backups exclude `secrets/`, `oauth/`, `token.json`, `secrets.key`, and `secrets.vault.enc`. DPAPI blobs are user/PC-bound and non-portable.
   - `StagedUpdater.auto_install_enabled` remains **disabled (`False`)** until signed builds with a trusted Authenticode certificate are available.

7. **Supply Chain**:
   - Python runtime pinned via `requirements.lock` (38 verified packages; zero known CVEs reported by `pip-audit` at verification time; license policy enforced via `tools/check_licenses.py`).
   - Embedded `cloudflared.exe` (`2026.11.2`) pinned by SHA-256 and verified Cloudflare Authenticode certificate (`packaging/cloudflared.json`).
   - CycloneDX SBOM (`SBOM.cdx.json`) and `SHA256SUMS.txt` generated per build.
   - **Current Signing Gap**: Release executables are **unsigned** locally and in CI because no owner Authenticode `.pfx` certificate is configured (`BLOCKED`).
