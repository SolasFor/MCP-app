# Changelog

## [1.0.0] - 2026-11-25 (Stage 12: Stable Release Prep)
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
