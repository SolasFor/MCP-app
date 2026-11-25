# Automation, Monitoring, MCP Playground, Backup & Staged Updater (`v0.9.9`)

Stage 11 adds deterministic automation, runtime telemetry, a localhost-only Admin REST API, a live MCP Playground, schema-versioned configuration backup/restore, a staged updater, and headless startup (`--headless`).

## 1. Automation Scheduler (`backend/automation/scheduler.py`)

- **Triggers**: 5-field cron (`minute hour day month weekday`), fixed interval (`>= 5s`), application `startup`, and named internal `event` triggers.
- **Timezone & DST**: Supports `UTC`, `local`, fixed `+HH:MM` offsets, and IANA `ZoneInfo` names (with graceful UTC fallback if minimal environments omit `tzdata`), walking UTC minutes through local DST transitions.
- **Misfire & Concurrency Policies**:
  - `misfire_policy`: `skip` (advance to next slot and log `skipped_misfire`), `coalesce`, or `run_once`.
  - `concurrency_policy`: `forbid` (skips overlapping run as `skipped_concurrency`) or `allow`.
  - **Idempotency**: Deduplicates repeated slots/events by `schedule_id:idempotency_key:slot_tag`.
- **Safe-only Retries**: Schedules with `safe_retry=False` **refuse** automatic retries (`max_retries > 0`). Only explicitly safe schedules may retry up to 3 times.
- **Live Permission Recheck & Revoke**: Before executing, `AutomationScheduler` runs `permission_checker(spec)` against OAuth approvals and Emergency Stop. Revoked or unauthorized schedules automatically transition to `enabled=False` (`paused_revoked`) with a local notification.
- **Mutation Guard**: Creating or deleting schedules programmatically requires `actor_id="owner"` or `actor_profile="full"`.

## 2. Monitoring, Audit Viewer & Diagnostics (`backend/automation/monitoring.py`)

- `MetricsRegistry` tracks total requests, error counts, and per-tool call counts, error counts, average latency (ms), and p95 latency (ms).
- `collect_system_snapshot` gathers host CPU/RAM/disk usage (`psutil`), MCP telemetry, OAuth client summaries, tunnel status, gateway count, and scheduler counts.
- `filter_audit_entries` & `prune_audit_file` provide case-insensitive audit filtering and atomic log retention trimming.
- `export_redacted_diagnostics` outputs a `schema_version=1` JSON diagnostic bundle with all tokens and registered secrets scrubbed via `SecretRedactor`.

## 3. Localhost-Only Admin REST API (`backend/automation/admin_api.py`)

`build_local_admin_app()` in `backend/server.py` exposes local administrative routes strictly separate from the public `/mcp` Starlette app:

- `GET /api/v1/monitoring` (`admin:read`)
- `GET /api/v1/schedules` (`admin:read`)
- `POST /api/v1/schedules/{schedule_id}/run` (`admin:write`)
- `GET /api/v1/diagnostics/export` (`admin:read`)

Security enforcement:
- Strictly loopback `Host` (`127.0.0.1`, `localhost`, `::1`, `[::1]`) and loopback client IP (`127.0.0.1`, `::1`, `localhost`).
- Rejects tunnel forwarding headers (`Cf-Ray`, `Cf-Connecting-Ip`, `X-Forwarded-For`, `X-Forwarded-Host`, `Ngrok-Trace-Id`, `Tailscale-User-Login`) with HTTP `403`.
- Constant-time (`hmac.compare_digest`) scoped bearer/`X-MCP-Admin-Token` authentication (`401` missing/invalid, `403` insufficient scope).
- Never mounted onto public Cloudflare / ngrok / Tailscale / OpenAI endpoints.

## 4. MCP Playground (`AutomationPage` & `backend/server.py:invoke_playground_tool`)

- **LIVE EXECUTION WARNING**: The Playground executes tools against real local stores/endpoints inside the selected profile (`safe`, `allowlist`, `full`), never mocked success. Avoid running mutating commands against production files without backups.
- Supports testing both **allowed** calls (e.g., `server_info` under `safe`, `device_list` under `allowlist`) and **denied** calls (e.g., `oauth_windows_command` under `safe`).
- Ephemeral OAuth test principals created for full backend Playground tests are immediately revoked in a `finally:` block.

## 5. Redacted Backup/Restore & Staged Updater (`backend/automation/backup_updater.py`)

- `BackupManager` exports versioned (`schema_version = 1`) configuration ZIPs with SHA-256 manifest verification and a pre-restore rollback snapshot (`.pre_restore_backup.zip`).
- Secrets (`secrets/`, `oauth/`, `token.json`, `secrets.key`, `secrets.vault.enc`) are **excluded by default**.
- **DPAPI Non-Portability**: Windows DPAPI-protected keys and vaults are bound to the originating Windows user and machine and **cannot** be decrypted on another PC or user account.
- Zip-slip path traversal, symlink entries, oversized payloads, and SHA-256 mismatches are rejected fail-closed; restore errors roll back atomically from `.pre_restore_backup.zip`.
- `StagedUpdater` parses GitHub Release metadata, enforces both SHA-256 and trusted **Ed25519** signature verification before staging, creates pre-apply rollback snapshots, and keeps **`auto_install_enabled = False`** pending trusted Authenticode release signing.

## 6. Headless Mode & Windows Service Session 0 Separation

- `python main.py --headless` / `MCPApp.exe --headless` runs the MCP backend without Qt/GUI.
- **Session 0 Isolation**: If deployed as a background Windows Service (`--headless`), **Computer Use (`desktop_*`)** cannot capture or control an interactive desktop (`WinSta0\Default`) from Session 0 and must run via a separate interactive user-session agent. MCP-app never modifies existing system services automatically without explicit owner action.
