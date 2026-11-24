# MCP-app 0.8.5: PowerShell and managed development servers

## Windows / SSH
For an approved OAuth client with Full Access, call oauth_windows_command
with command, shell ("cmd" or "powershell"), and timeout (1–600 seconds).
Default shell remains CMD for existing clients. The allowlist still uses
direct execution, exact rules and its original maximum timeout of 15 seconds.
Full Access accepts commands/scripts up to 65536 characters. CMD has a smaller
Windows command-line limit; longer PowerShell scripts use a temporary .ps1
file subject to the local execution policy. No execution-policy bypass is used.
SSH supports a configurable command timeout in Full Access and still verifies
host keys. Network and client timeouts can be shorter than these settings.

## Managed servers
The optional oauth_managed_server tool is visible only in Full Access.
Create managed_servers.json in the backend working directory (normally
%APPDATA%\MCPApp\server). Example, replacing paths with real local paths:

```json
{
  "dev": {
    "argv": ["C:\\project\\.venv\\Scripts\\python.exe", "-m", "http.server", "8080", "--bind", "127.0.0.1"],
    "cwd": "C:\\project"
  }
}
```

Use action=list to discover configured profiles, action=start with name=dev
to launch, and action=stop with name=dev to terminate that direct child.
There are no remote configuration or arbitrary argument inputs in this tool.
Process ownership is per OAuth client; status is tracked using live process
handles, not reusable PIDs. The process output is discarded, not returned to
the client. The direct managed children are stopped on normal backend exit;
abrupt termination, detached descendants and independently launched commands
are not guaranteed to stop. Revoking OAuth blocks subsequent requests but does
not retroactively kill arbitrary processes. No sandbox is provided.

## Security
Safe remains the default. Existing allowlists and OAuth settings are retained.
Full Access is intentionally powerful and must only be granted to trusted
clients. The app does not override external client-side execution restrictions.
No automatic elevation, bypass of Windows policy, or suppression of explicitly
opened GUI application windows is provided.
