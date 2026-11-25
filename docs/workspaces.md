# Workspaces (`v0.9.5`)

MCP-app Workspaces provides a guarded per-project registry (`%APPDATA%\MCPApp\workspaces\workspaces.json`) for browsing, searching, editing, testing, and running safe Git workflows on owner-registered local directories.

## Granular Per-Project & Per-Client Permissions
Each workspace defines default permissions (`read`, `write`, `delete`, `execute`, `git`), defaulting to read-only (`read=True`, everything else `False`), plus optional `client_permissions[client_id]` overrides, `allowed_clients`, and `min_profile`.

## Windows Path Security & Honest Boundaries
- **Canonical Resolution & Reparse Protection**: Rejects `..` traversal, absolute paths, UNC paths (`\\server\share`), device prefixes (`\\?\`, `\\.\`), Windows reserved names (`CON`, `NUL`, `COM1..9`, etc.), NTFS Alternate Data Streams (`:`), `.git`, `.env*`, key/certificate suffixes, symlinks, and Windows NTFS junctions (`FILE_ATTRIBUTE_REPARSE_POINT`) at every path segment.
- **Opened-Handle Verification**: After opening a file descriptor, `verify_opened_fd` re-verifies the actual OS handle target via `GetFinalPathNameByHandleW` on Windows or `(st_dev, st_ino)` `fstat`/`lstat` matching on POSIX.
- **Optimistic Version Precondition**: Modifying existing files (`workspace_write_file`, `workspace_apply_patch`, `workspace_delete_file`) requires matching `expected_sha256` to prevent clobbering concurrent user edits. All writes are atomic and save local rollback snapshots (`WorkspaceHistory`).
- **Untrusted Git Hooks Suppressed**: When `trust_git_hooks` is `False` (default), Git commands run with empty `core.hooksPath`, disabled `fsmonitor`, `credential.helper`, `ext::`, and filters, plus `--no-verify` on `git commit`.
- **Honest Boundary**: Specialized `workspace_*` and `git_*` tools enforce these guards fail-closed. **Full Access CMD/PowerShell (`oauth_windows_command` with `full` profile) is NOT sandboxed** and runs with the current OS user's full privileges.
