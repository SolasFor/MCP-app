# OAuth 2.1 for MCP-app (PR-04 / initial integration)

This uses the official MCP Python SDK OAuth flow. Every owner-approved
OAuth client shares the owner's selected global execution scenario: safe
(default, no commands), exact allowlist, or full access. Command execution
in the last two modes occurs immediately without additional confirmation. It is intended for interoperability testing with Gemini
Developer Mode, Notion, and other OAuth-capable MCP clients. **A successful
browser authorization does not guarantee a service's own plan/region or SSE
requirements are met.**

## Connecting over Cloudflare Quick Tunnel

1. Start MCP app in **Quick Connect** and copy the current
   `https://<random>.trycloudflare.com/mcp` URL.
2. Add this URL as a custom MCP server in an eligible client.
3. The client discovers the RFC 9728 resource metadata and RFC 8414 OAuth
   metadata, then registers itself dynamically using `/register`.
4. Its authorization browser opens `/authorize`, which redirects to a local
   MCP-app **owner consent page** on the same HTTPS origin.
5. Check the client name, callback URL, and the displayed current execution
   scenario (especially if Full Access is enabled).
   Enter the **existing owner token displayed in the Windows MCP app** on
   that consent page and click **Allow**. Do not send the token to the client.
6. The official MCP SDK verifies PKCE S256 during `/token` exchange.
7. The client receives a short-lived access token with the compatibility
   scope `mcp:read`. In safe mode it sees only `server_info`; in allowlist
   and full modes it additionally sees `oauth_windows_command` and
   `oauth_ssh_command`. Allowed commands run immediately without further
   per-call approval. The current policy applies to existing tokens too.

The owner token itself remains usable via manual
`Authorization: Bearer ...` authentication. It is **never placed in an OAuth
redirect URL**, and the consent page does not set authentication cookies.

## OAuth endpoints (served by MCP SDK)

- `/.well-known/oauth-protected-resource/mcp` (also canonical variants
  supported by SDK)
- `/.well-known/oauth-authorization-server`
- `/register` (public DCR, bounded to 128 clients)
- `/authorize`
- `/oauth/consent`
- `/token`
- `/revoke`
- `/mcp` (protected MCP endpoint)

`/oauth/consent` requires a **same-origin POST** (`Origin`, `Sec-Fetch-Site`, and double-submit `csrf_token` cookie+form check) and the owner's token.
Pending requests expire after five minutes and wrong-owner-token attempts
are limited to five per request (showing an inline retry form for attempts 1–4).
Consent responses forbid caching and framing (`Cache-Control: no-store`, `X-Frame-Options: DENY`), adapt cleanly to Dark/Light `prefers-color-scheme` and RU/EN (`MCP_LANGUAGE` / `Accept-Language`), display a prominent high-risk notice when `full` access applies, accept exact arbitrary UTF-8 owner secrets (`MCP_OWNER_SECRET_B64`) without stripping whitespace while maintaining a separate HTTP-safe Bearer transport token (`MCP_SECRET_TOKEN`), and dynamically scope CSP `form-action 'self' <validated client callback origin>` only for the approved/pending client's redirect target so Chromium browsers (Chrome, Edge) cleanly complete cross-origin 303 redirects after form POST.

## Supported grant behavior

- Authorization Code with PKCE S256 verification performed by the SDK.
- DCR with scope `mcp:read` only. Invalid scopes are rejected.
- One-use authorization codes (300s).
- Access token TTL 1 hour.
- Refresh token TTL 7 days and rotation on use.
- Revocation of an access or refresh token revokes its token family.
- Resource (audience) is the current `MCP_PUBLIC_URL`.
- An old Quick Tunnel URL's tokens are rejected by the new process.

**Storage since PR-05**: OAuth registrations and tokens now survive backend
restarts with the **same public URL**, using encrypted SQLite and the Windows
user's DPAPI-protected data key. The GUI can list registered/approved clients
and revoke access immediately. Quick Tunnel URL rotation still invalidates
the previous URL's grants. In-progress OAuth authorization codes remain
short-lived and process-local.

In allowlist/full modes, no per-command consent exists. Windows execution
is **not** isolated in an OS sandbox. See [three execution scenarios](oauth-fixed-windows-ssh.md)
and [OAuth persistence](oauth-persistence.md).

## Security boundary: Standard vs Advanced

With OAuth enabled, the server ignores legacy Advanced/Execution toggles.
In safe mode only `server_info` is exposed; in allowlist/full modes Windows
and SSH tools are visible. There are no per-client rights toggles or
workspace/note tools. Allowlist requires exact configured rules, while full
mode permits arbitrary shell commands. The log warns when a legacy Advanced
setting is overridden.

Administrators using Advanced tools with manual Bearer tokens can set
`enable_oauth=false` and explicitly enable Advanced/Execution flags.
Do not disable OAuth for a public/cloud client that needs it.

The OAuth approval secret currently is the existing owner Bearer token.
**It grants the owner's existing privileges and must be handled as a
password**. Never share it with an app, put it in a URL, or type it on a page
whose origin is not the current MCP-app HTTPS hostname.

Actual execution occurs with the Windows user's existing privileges.
The current design is not an OS sandbox; only authorize trusted OAuth
clients and review the full-access warning before enabling it.

## Testing

- CI tests the provider's consent requirement, code replay prevention,
  token rotation and revocation, allowed resource, origin checks, and an
  in-memory reset on a new Quick URL.
- CI checks OAuth routes, safe/allowlist/full scenarios, immediate allowed
  command execution and switching profiles through the actual installed SDK.
- Actual Windows + cloudflared and Gemini / Notion sign-in must still be
  tested manually and documented; plans and regional availability can block
  those integrations independent of server quality.
