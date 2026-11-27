# Workspaces & Managed Servers (`v1.0.2` / N03)

MCP-app Workspaces provides the single unified UI and project registry (`%APPDATA%\MCPApp\workspaces\workspaces.json`, schema v2) combining guarded per-project file/Git/task operations with local Server Manager lifecycle control (`%APPDATA%\MCPApp\servers\managed_servers.json`).

## Single Authoritative Server Linkage (`WorkspaceProfile.linked_servers`)
- **1:N & N:1 Links Without Duplication**: Workspaces reference existing `ServerProfile` IDs via `WorkspaceProfile.linked_servers` (`WorkspaceServerCoordinator` in `backend/workspaces/server_links.py`) without creating a parallel server registry or duplicating DPAPI secrets.
- **Unlinked Servers Section**: All unlinked, ambiguous, or standalone servers remain visible and manageable in the **Unlinked Servers** tab inside Workspaces.
- **Non-Destructive Unlink & Delete**: Unlinking a server or removing a workspace entry only updates the workspace registry (`workspaces.json`) and workspace secrets — it **never** stops or deletes managed server profiles or detached `independent` processes.
- **Lossless v1→v2 Migration & Fail-Closed Corruption Handling**: Migrating v1.0.2 configs creates `.json.v1.bak` backups with user-private ACLs, preserves all IDs/secrets/permissions, and **never** guesses workspace-to-server associations by `cwd` or name. Corrupt JSON fails closed with an error banner without overwriting disk files.

## Cross-Layer Permissions & Task History
- **Fail-Closed Intersection**: Operating on a linked server intersects **Global OAuth Profile ∩ Workspace Permissions ∩ ServerProfile (`min_profile`, `allowed_clients`) ∩ Task Permissions**.
- **Pre-Launch Confused-Deputy Guard**: Starting a server that declares `depends_on` validates caller authorization on every dependency workspace/server before launching any process.
- **Workspace Task Manager Audit**: Running named workspace commands (`workspace_run_task` or GUI **Run Task**) records real `TaskRecord` entries in `TaskStore`, stores `result.json` artifacts, and appends `task_id` to `WorkspaceProfile.linked_tasks`.

## Granular Per-Project & Per-Client Permissions
Each workspace defines default permissions (`read`, `write`, `delete`, `execute`, `git`), defaulting to read-only (`read=True`, everything else `False`), plus optional `client_permissions[client_id]` overrides, `allowed_clients`, and `min_profile`.

## Windows Path Security & Honest Boundaries
- **Canonical Resolution & Reparse Protection**: Rejects `..` traversal, absolute paths, UNC paths (`\\server\share`), device prefixes (`\\?\`, `\\.\`), Windows reserved names (`CON`, `NUL`, `COM1..9`, etc.), NTFS Alternate Data Streams (`:`), `.git`, `.env*`, key/certificate suffixes, symlinks, and Windows NTFS junctions (`FILE_ATTRIBUTE_REPARSE_POINT`) at every path segment.
- **Opened-Handle Verification**: After opening a file descriptor, `verify_opened_fd` re-verifies the actual OS handle target via `GetFinalPathNameByHandleW` on Windows or `(st_dev, st_ino)` `fstat`/`lstat` matching on POSIX.
- **Optimistic Version Precondition**: Modifying existing files (`workspace_write_file`, `workspace_apply_patch`, `workspace_delete_file`) requires matching `expected_sha256` to prevent clobbering concurrent user edits. All writes are atomic and save local rollback snapshots (`WorkspaceHistory`).
- **Untrusted Git Hooks Suppressed**: When `trust_git_hooks` is `False` (default), Git commands run with empty `core.hooksPath`, disabled `fsmonitor`, `credential.helper`, `ext::`, and filters, plus `--no-verify` on `git commit`.
- **Honest Boundary**: Specialized `workspace_*` and `git_*` tools enforce these guards fail-closed. **Full Access CMD/PowerShell (`oauth_windows_command` with `full` profile) is NOT sandboxed** and runs with the current OS user's full privileges.
