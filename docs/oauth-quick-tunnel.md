# OAuth 2.1 for MCP-app (PR-04 / initial integration)

This implements the first **read-only** OAuth flow through the official
Python MCP SDK. It is intended for interoperability testing with Gemini
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
5. Check the client name, callback URL, and requested read-only permission.
   Enter the **existing owner token displayed in the Windows MCP app** on
   that consent page and click **Allow**. Do not send the token to the client.
6. The official MCP SDK verifies PKCE S256 during `/token` exchange.
7. The client receives a short-lived access token with the single scope
   `mcp:read` and may invoke the safe `server_info` tool.

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

`/oauth/consent` requires a **same-origin POST** and the owner's token.
Pending requests expire after five minutes and wrong-owner-token attempts
are limited to five per request. Form responses forbid caching and framing.

## Supported grant behavior

- Authorization Code with PKCE S256 verification performed by the SDK.
- DCR with scope `mcp:read` only. Invalid scopes are rejected.
- One-use authorization codes (300s).
- Access token TTL 1 hour.
- Refresh token TTL 7 days and rotation on use.
- Revocation of an access or refresh token revokes its token family.
- Resource (audience) is the current `MCP_PUBLIC_URL`.
- An old Quick Tunnel URL's tokens are rejected by the new process.

**Limitations of this PR**: registrations and tokens are intentionally
process-local. All OAuth clients must re-register and reauthorize after an
app restart, including named-domain mode. This is not yet a durable production
authorization server. A later PR must add secure persistent client/token
storage, revocation management in GUI, and per-client consent/scopes.

## Security boundary: Standard vs Advanced

With OAuth enabled, the server **forces the Standard tool profile** even if
`enable_advanced_tools=true` is saved in settings. OAuth tokens never grant
filesystem/command/SSH tools. The log shows a warning when an Advanced
setting is overridden.

Administrators using Advanced tools with manual Bearer tokens can set
`enable_oauth=false` and explicitly enable Advanced/Execution flags.
Do not disable OAuth for a public/cloud client that needs it.

The OAuth approval secret currently is the existing owner Bearer token.
**It grants the owner's existing privileges and must be handled as a
password**. Never share it with an app, put it in a URL, or type it on a page
whose origin is not the current MCP-app HTTPS hostname.

We do not currently isolate privileged work in a Windows sandbox, and this
OAuth implementation must not be treated as approval for privileged access.

## Testing

- CI tests the provider's consent requirement, code replay prevention,
  token rotation and revocation, allowed resource, origin checks, and an
  in-memory reset on a new Quick URL.
- CI checks OAuth routes and the default safe tool registry via the actual
  installed SDK.
- Actual Windows + cloudflared and Gemini / Notion sign-in must still be
  tested manually and documented; plans and regional availability can block
  those integrations independent of server quality.
