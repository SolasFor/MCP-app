# Changelog

## [1.0.0] - 2026-11-26 (Stage 12: Stable Release, Acceptance Fixes & Minimalist UI Redesign)
- **Minimalist Compact Desktop UI Redesign (`DESIGN.md`, `app/ui/**`)**:
  - Redesigned the full desktop interface in a compact Linear/Raycast/Docker Desktop graphite aesthetic (`#151617` dark / `#F7F8F9` light, `960×640` default / `800×540` min, `184 px` / `52 px` sidebar), reserving green strictly for primary server Start/Stop controls and live running indicators while switching secondary actions to neutral graphite.
  - Replaced nested and parameter-level cards with flat `Section` / `SettingRow` / `Divider` layouts, wrapping `FlowLayout` toolbars across management pages, single-bar `CopyField`, and unified `SilentDialog` styling; removed all decorative animations (`SpotlightFrame`, `ShinyLabel`, `SparkButton`, `reveal`, `StatusDot` pulse halo), preserving only the OS-animation-aware `150 ms OutCubic` `ToggleSwitch` transition.
  - Documented tokens, typography, spacing, and non-regression UI rules in `DESIGN.md`, refreshed `docs/screenshots/`, expanded `tools/capture_ui_screenshots.py` for `1.0–2.0` DPI (`175%` included), and added `tests/integration/test_minimalist_ui_redesign.py` (`break-ui`, responsive sizes, shortcuts, accessibility, and animation guard).
- **Additional UI Fixes (Wave 3 on `fix/v1.0.0-acceptance-fixes`)**:
  - **Security — Computer Use (`app/ui/pages/security_page.py`, `app/ui/components/toggle_switch.py`, `backend/desktop/{models,manager}.py`)**: Removed «Остановить Computer Use» (`Stop Computer Use`) button and its empty layout row while preserving the internal emergency stop (`DesktopPolicyStore.set_emergency_stop`, `ServiceManager.emergency_stop`, conditional `Clear Emergency Stop`). Disabling the master Computer Use `ToggleSwitch` now greys out and locks all dependent toggles (with `allow_secret_typing` additionally requiring `allow_input_control`) while preserving their stored values, immediately disables all Computer Use MCP tools via `ToolRegistry` / `DesktopManager`, and auto-saves silently across restarts. Moved «Сценарий доступа по умолчанию» (`SafeComboBox`) into `SecurityPage` («Политика выполнения команд»).
  - **Logs (`app/ui/pages/logs_page.py`, `app/ui/components/log_viewer.py`)**: Removed the «Экспорт диагностики…» (`Export Diagnostics…`) button from the Logs toolbar and removed the explanatory subtitle `logs.lead` (RU/EN) along with blank spacing, replacing the button with plain redacted text log export (`Экспорт…` / `Export…`) while preserving all log disk persistence, filtering, search, tail paging, copy, clear, open-folder, auto-scroll, and the internal `app/core/diagnostics_bundle.py` module.
  - **Home (`app/ui/pages/home_page.py`, `app/ui/main_window.py`)**: Completely removed the «Доступ и AI-клиенты» card, buttons, explanatory text, spacing, and exclusive signals/slots (`HomePage` now displays Hero Engine + Client Endpoint cleanly; default access policy moved to `SecurityPage` and per-client overrides remain on `ClientsPage`).
- **Release Acceptance Wave 2 Fixes (`fix/v1.0.0-acceptance-fixes`)**:
  - **Windows `_internal` Optimization (kept `onedir`)**: Stripped `opengl32sw.dll`, 97 unused `.qm` locales (keeping `qtbase_ru.qm`/`qtbase_en.qm`), unused Qt image/TLS/platform plugins, duplicate CRT DLLs, and build-only `.dist-info` artifacts while adding explicit `copy_metadata("mcp", "pydantic", "paramiko", "cryptography")` in `packaging/mcp_app.spec`. Reduced `dist/MCPApp/_internal` from `160.37 MB` (`323` files / `72` dirs) to `130.94 MB` (`166` files / `62` dirs, **-29.43 MB / -157 files**) and `MCPApp-1.0.0-portable.zip` from `67.06 MB` (`70,316,210` B) to `55.38 MB` (`58,066,712` B).
  - **Centralized Persistent Logging & Redacted Diagnostics (`app/core/logging_manager.py`, `app/core/diagnostics_bundle.py`)**: Writes structured multi-process-locked logs to `%APPDATA%\MCPApp\logs\` across 15 component files + `.gz` `archive/`, mirrors errors cleanly to `errors.log`, persists unhandled crashes in `crash.log`, preserves protected security audits (`mcp_execution_audit.jsonl`, `desktop_policy_audit.jsonl`), redacts secrets/PKCE/codes/cookies/screenshots even at `DEBUG`, adds `SettingsPage` logging controls, and redesigns `LogsPage` with component/level selectors, error counter, async tail paging, Open Logs Folder, and redacted Diagnostic ZIP export.
  - **Minimal Notifications**: Removed redundant theme-change toast and minimize-to-tray popup while keeping tray minimization, error reporting, and Full Access warnings.
  - **Simplified Providers & Loopback UI Removal**: Removed `Не найден`/`Установлен`/`Доступен`/version/`Loopback` badges and removed `local_only` from selectable UI providers (4 UI providers remain: CF Quick, CF Named, ngrok, Tailscale Funnel; legacy `local_only`/`openai_tunnel` migrate safely to `PROVIDER_NONE`), while preserving internal headless/Admin loopback testing.
  - **Custom Domain Switch Persistence & Dual Mode DomainWizard**: Stopped wiping `public_url`/provider state across switches (`Named -> Quick/ngrok/Tailscale -> Named` + restarts), added DomainWizard mode to connect an existing tunnel via **Cloudflare Tunnel Token** + domain without API Token or DNS edits, added explicit owner MCP Owner Token Paste/manual UX clearly separated from Cloudflare/ngrok credentials, and classified exact domain diagnostics (`agent_missing`, `secret_decrypt_failed`, `domain_not_configured`, `domain_invalid`, `token_missing`, `token_invalid`).
  - **Computer Use `ToggleSwitch` Auto-Save**: Replaced 4 checkboxes with animated theme-aware `ToggleSwitch` controls (`app/ui/components/toggle_switch.py`), removed manual Save button, and applied changes atomically (`DesktopPolicyStore.update`) & live without restart, with silent rollback warnings on I/O errors.
  - **Full Proxy System Overhaul (`app/core/proxy.py`, `app/ui/proxy_page.py`)**: Removed fake default `127.0.0.1:1080`; added `none` (default), `auto` (WinINET/WinHTTP/ENV/PAC/known VPN ports with real protocol+auth+TLS handshake, zero silent direct fallback), and `manual` (`SOCKS5H`/`SOCKS5`/`HTTP CONNECT` + DPAPI credentials) with background diagnostics and honest ngrok (`HTTP_PROXY` only) / Tailscale (direct daemon) handling.
  - **Chromium/Edge OAuth Authorization Fix (`backend/oauth_provider.py`, `backend/server.py`)**: Dynamically scoped CSP `form-action` on `/oauth/consent` GET and 303 redirect responses strictly to `'self'` + that request's validated client `redirect_uri` origin/scheme (fixing Chromium's post-POST 303 redirect CSP block), added canonical Origin + `Sec-Fetch-Site` + CSRF cookie/form validation, inline retry HTML form on incorrect owner token, clear HTML `/authorize` error pages for browser requests, and verified live with Playwright across Chromium, Google Chrome, Microsoft Edge, and Firefox.
- **Release Acceptance Wave 1 Fixes**:
  - Set `allowlist` as first-launch default access profile (configurable before server start, persisted across restarts, inherited by new OAuth contexts/clients while preserving individual profiles and fail-closed `safe` fallbacks).
  - Replaced `QComboBox` with wheel-safe `SafeComboBox` across all pages/dialogs and replaced topbar cycling theme button with a Light/Dark/System `SafeComboBox` synced with `SettingsPage`.
  - Replaced all `QMessageBox` / audible `QSystemTrayIcon.showMessage` calls with silent `SilentDialog` / `SilentMessageBox` / `SilentNotificationPopup` (zero alert sounds without muting Windows).
  - Eliminated ~1s theme-switch freeze (<200ms visible update) via cached toggle PNGs/QSS/palette, one-time style/font init, lazy hidden-page theming, and removing blocking CLI probes from theme updates.
  - Fixed OAuth client reconnect after owner-token rotation (preserve DCR client registration with `approved_at=NULL`, revoke issued tokens and overrides, restart backend without tearing down active tunnel).
  - Completely removed OpenAI Secure MCP Tunnel (`openai_tunnel`) with safe migration to `local_only` and optional owner cleanup of `tunnel/openai_tunnel_api_key` (5 transports remain).
  - Fixed live per-client permissions & live Computer Use `desktop_*` gating (`tools.listChanged=True` + `notifications/tools/list_changed`), enriched `server_info` (`profile`, `computer_use`, `server_mode`), and cleaned Home/Security cards.
- Completed final security review and documented full threat model (`docs/threat-model-v1.md`), honest transport/client compatibility matrix (`docs/compatibility-matrix.md`), upgrade guide (`docs/upgrade-guide.md`), complete MCP tool reference (`docs/tool-reference.md`), and release notes (`docs/releases/v1.0.0.md`).
- Added E2E `v0.8.5 -> v1.0.0` upgrade migration, resilience, mid-flight OAuth revoke, output flood, and tracked-file secret scan tests (`tests/integration/test_release_1_0_0.py`).

## [0.9.9] - 2026-11-25 (Stage 11: Automation & Monitoring)
- Added `backend/automation/` (`scheduler.py`, `monitoring.py`, `admin_api.py`, `backup_updater.py`) with 5-field cron + TZ/DST resolution, misfire/concurrency/idempotency policies, safe-only retries, live permission revoke auto-pause, `MetricsRegistry`, `psutil` snapshots, redacted diagnostics export, audit filtering/pruning, loopback-only scoped Admin REST API rejecting tunnel headers, schema-v1 non-secret `BackupManager` with atomic rollback, and `StagedUpdater` (Ed25519 + SHA-256 verification, auto-install disabled).
- Added `--headless` CLI backend entrypoint and `AutomationPage` (Schedules, Monitoring, live-warned MCP Playground, Backup & Staged Updates), promoted `automation` to primary sidebar, and eliminated redundant Fusion restyle / singleton signal leaks.

## [0.9.8] - 2026-11-25 (Stage 10: Remote Management)
- Added `backend/remote/` with strict `RejectPolicy` `known_hosts`, safe `~/.ssh/config` importer, `SecretStore("ssh")`, canonical SFTP roots & symlink guards, 12 `REMOTE_TOOLS` (`device_*`, `ssh_*`, `sftp_*`, `remote_*`) preserving `oauth_ssh_command`, and `DevicesPage`.

## [0.9.7] - 2026-11-25 (Stage 9: Extensions)
- Added out-of-process JSON-RPC extension runtime (`--run-extension`), manifest & Ed25519/SHA-256 package verifier, 4 official starter extensions + starter template, 6 `extension_*` OAuth tools, and `ExtensionsPage`.

## [0.9.6] - 2026-11-25 (Stage 8: Computer Use)
- Added isolated 64-bit Win32/UIA `backend/desktop/` (`PrintWindow`/`BitBlt` memory-only screenshots, UIA tree/invoke/type/drag/scroll, UAC/locked-desktop/UIPI/password-field guards), 13 `desktop_*` tools, `SecurityPage` opt-in & topbar Emergency Stop.

## [0.9.5] - 2026-11-24 (Stage 7: Workspaces)
- Added `backend/workspaces/` with canonical/junction/ADS/secret path guards, SHA-256 optimistic concurrency, edit rollback history, venv task runner, Git controls, 18 `workspace_*` + `git_*` tools, and `WorkspacesPage`.

## [0.9.4] - 2026-11-24 (Stage 6: Server Manager)
- Added `backend/servers/` with built-in templates, dependency DAGs, port conflict probes, readiness checks, SecretStore env injection, auto-restart backoff, 8 `server_*` tools, and `ServersPage`.

## [0.9.3] - 2026-11-24 (Stage 5: Task Manager)
- Added `backend/tasks/` SQLite task persistence (`SCHEMA_VERSION`), async cancellation, recovery after restart, retention cleanup, 8 `task_*` tools, and `TasksPage`.

## [0.9.2] - 2026-11-24 (Stage 4: MCP Gateway)
- Added `backend/gateway/` multi-upstream router (`stdio`, `Streamable HTTP`, `SSE`), loop-header defense, collision-safe routing, `solidworks_mcp_template`, and `GatewayPage`.

## [0.9.1] - 2026-11-24 (Stage 3: Connection Manager)
- Added `app/core/tunnels/` unifying all 6 transports (Cloudflare Quick, Cloudflare Named, ngrok, Tailscale Funnel, OpenAI Secure MCP Tunnel, Local only), `RouteOwnershipStore`, issuer-transition guards, and `ConnectionsPage`.

## [0.9.0] - 2026-11-24 (Stage 2: UI Redesign)
- Redesigned PyQt6 UI in Linear + Docker Desktop style with Dark/Light/System themes (WCAG AA contrast), live RU/EN i18n, collapsible sidebar (`Ctrl+B`), Command Palette (`Ctrl+K`), Toast notifications, and HiDPI support.

## [0.8.6] - 2026-11-24 (Stage 1: Stability & Security)
- Added Windows Job Objects, DPAPI/Credential Manager `SecretStore`, `ProcessRunner`, bounded `output_stream` with disk spooling, unified `ToolRegistry` (`SCHEMA_VERSION=2`), `?token=` removal, pinned `requirements.lock` + `cloudflared.json`, license check, SBOM, `pip-audit`, and `--selftest`.
