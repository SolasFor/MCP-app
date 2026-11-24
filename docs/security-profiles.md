# Legacy administrator profiles (OAuth disabled)

> **Актуальный OAuth-режим (v0.8.6):** по умолчанию включён OAuth 2.1 (`enable_oauth=true`)
> с тремя сценариями доступа для каждого клиента (**Безопасный**, **Белый список**,
> **Полный доступ**), индивидуальными белыми списками, временными разрешениями и
> аварийной остановкой. Подробнее:
> [docs/oauth-fixed-windows-ssh.md](oauth-fixed-windows-ssh.md) и
> [docs/stability-security.md](stability-security.md).
> Дальнейшая информация на этой странице описывает **старый режим
> `enable_oauth=false`**, а не поведение OAuth-клиентов.

The default public profile intentionally exposes **only** `server_info`.
It is safe to use it to verify `tools/list` and `tools/call` through
Cloudflare Quick Tunnel. This does **not** make OAuth clients work yet.

## Why this changed

Before PR-03, anyone holding the single Bearer token could invoke
`run_local_command`, `run_ssh_command`, and read/write the workspace.
A token is not a per-operation consent mechanism. Public clients should
not automatically inherit administrator permissions.

## Default (recommended)

In `%APPDATA%\MCPApp\settings.json` on Windows:

```json
{
  "enable_advanced_tools": false,
  "enable_execution_tools": false,
  "allow_query_token": false
}
```

These settings are added automatically when the application writes a new
configuration. Existing installations retain their existing
`allow_query_token` setting; disable it manually if it was previously
enabled. Restart the server after changing settings.

The default server profile advertises only `server_info`.
`system://environment` is hidden, because it exposed local paths and SSH
configuration. This is a deliberate breaking change for security.

## Advanced workspace access (administrator opt-in)

Set `enable_advanced_tools` to `true` in the JSON file, leaving
`enable_execution_tools` at `false`, then restart.

This exposes `read_workspace_file`, `write_workspace_file`, and
`system://environment` along with `server_info`. File operations stay
inside `MCP_WORKSPACE_DIR` (defaults to the backend working directory),
reject common secret and credential paths, and limit read/write size.
These controls are defense in depth, not a full sandbox or protection from
concurrent malicious filesystem modifications.

**All clients using the same Bearer token gain the same Advanced rights.**
Do not enable this mode for untrusted external clients.

## Execution access (high-risk, manual administration only)

Set both settings to `true`, and *before starting MCP app* set process
environment variables containing exact allowlists:

```powershell
$env:MCP_ALLOWED_EXECUTABLES = "whoami.exe,hostname.exe"
$env:MCP_ALLOWED_HOSTS = "my-trusted-ssh-alias"
```

Only explicitly listed executables are registered as `run_local_command`.
Commands use `create_subprocess_exec`, not a shell. The executable must be
resolved to an absolute path, and Windows `.bat`/`.cmd` wrappers are
rejected. Allowlisting interpreters or tools that themselves execute commands
defeats this protection; avoid doing that.

`run_ssh_command` registers only with an explicit non-empty host allowlist.
Unknown SSH host keys are rejected and must be enrolled in
`%USERPROFILE%\.ssh\known_hosts` via a trusted process.

An empty allowlist never means "allow all". A wildcard such as
`*.example.com` is invalid. The optional environment variables are
inherited by the child process from MCP app.

**Do not enable execution for internet-connected clients** until
client-specific OAuth scopes, locally approved actions, and stronger
sandboxing are implemented.

## Bearer token and Quick Tunnel

Use the current HTTPS URL, for example
`https://random.trycloudflare.com/mcp`. Prefer the header
`Authorization: Bearer <secret>`. Query-string tokens are disabled by
default for new installations and should not be shared in URLs.

The Quick Tunnel URL changes when the tunnel is recreated. Clients must
update their connection. JSON-only transport does not support SSE-only
clients; that limitation is independent of tool permissions.

## Validation

- `python -m unittest discover -s tests/unit -p 'test_*.py' -v`
- `python -m unittest discover -s tests/integration -p 'test_*.py' -v`
- Use `mcp_probe.py` from PR #5 for an actual public HTTPS MCP test.
- Confirm that Standard `tools/list` reports only `server_info`.
- Confirm that a `tools/call` of `server_info` succeeds.
- Confirm privileged tool names are absent from Standard `tools/list`.

No GitHub unit/integration test can substitute for a real Windows + cloudflared
+ client interoperability test.

## Follow-up work

- OAuth 2.1 Authorization Server with per-client scopes and consent.
- Explicit GUI permission controls with clear warnings.
- Dedicated Windows sandbox for elevated command execution.
- Restricting token URL transport for upgrades and migration notices.
