# Upgrade Guide (`v0.8.5` / Legacy `SouronMCP` → `v1.0.0`)

## 1. Automatic Upgrade Behavior

1. **Legacy `SouronMCP` Data Migration**: On first launch of `MCPApp`, settings and stores under legacy `%APPDATA%\SouronMCP` are migrated non-destructively to `%APPDATA%\MCPApp`.
2. **`settings.json` Hardening**:
   - Legacy `allow_query_token: true` is automatically overridden/ignored (`ALLOW_QUERY_TOKEN = False` in backend and sanitized on load). Query-string credentials (`?token=`) are strictly rejected; clients must use OAuth 2.1 or `Authorization: Bearer ...`.
   - Legacy `tunnel_mode` (`"quick"` / `"named"`) maps cleanly to `active_provider` (`"cloudflare_quick"` / `"cloudflare_named"`) while preserving existing domain settings and UI defaults (`Dark`, `RU`, window geometry).
   - Legacy `active_provider` values `openai_tunnel` or `local_only` migrate safely to `none` (`PROVIDER_NONE`, no transport auto-started) and display a clear migration notice on the Connections page.
   - Legacy disabled `proxy.json` entries pointing to hardcoded `127.0.0.1:1080` migrate cleanly to `mode = "none"`.
   - Legacy `crash.log` and `server/mcp_audit.log` histories are non-destructively copied into `%APPDATA%\MCPApp\logs\archive\` during initial `LoggingManager` startup while keeping protected security audit files intact.
3. **`managed_servers.json` Schema Migration (v1 → v2)**:
   - Existing `v1` server definitions migrate automatically to `v2` (`ServerConfigStore.migrate_legacy_file`), creating a backup copy before writing and moving plain env secrets into DPAPI `SecretStore` where applicable.
4. **OAuth SQLite Migration (v1 → v2)**:
   - Existing registered clients (`clients` table) and issuer metadata remain preserved (`OAuthStore.schema_version() == 2`).
   - Per-client allowlists, time-bounded grants, and runtime emergency-stop tables are added automatically without invalidating approved OAuth clients unless the owner rotates `MCP_SECRET_TOKEN`.

## 2. DPAPI Non-Portability & Backup/Restore

- `BackupManager` (Automation tab) exports schema-versioned (`schema_version = 1`) ZIP archives of configuration JSON files **excluding secrets by default** (`secrets/`, `oauth/`, `token.json`, `secrets.key`, `secrets.vault.enc`).
- **Windows DPAPI secrets are tied to the Windows user SID and machine.** Moving `%APPDATA%\MCPApp\oauth\connections.key` or `%APPDATA%\MCPApp\secrets\` to a different Windows PC or user account will fail decryption. After migrating machines, regenerate tokens and re-authorize OAuth clients.
- Before applying any restore ZIP, `BackupManager` saves `.pre_restore_backup.zip` and rolls back automatically if writing a restored file fails.

## 3. Rollback & Uninstall

- **Application Rollback**: Keep a copy of the prior `MCPApp-<version>-portable.zip` or installer; `StagedUpdater.rollback_last(...)` restores staged backups on explicit owner action. Note that `auto_install_enabled` is **`False`** until trusted Authenticode signing is configured.
- **Uninstalling `MCPApp`**: Uninstalling the Windows program leaves user configuration, OAuth databases, logs, and SecretStore files intact under `%APPDATA%\MCPApp` so upgrades never erase client registrations. Remove `%APPDATA%\MCPApp` manually only if a full wipe is desired.
