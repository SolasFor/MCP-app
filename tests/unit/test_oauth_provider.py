"""OAuth provider regression tests without a live external service."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import time
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit

from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, RegistrationError, TokenError
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl
from starlette.requests import Request

from backend.oauth_provider import (
    LocalConsentOAuthProvider, READ_SCOPE, MAX_CLIENTS, token_digest,
)

ISSUER = "https://current.trycloudflare.com"
RESOURCE = ISSUER + "/mcp"
OWNER_SECRET = "owner-secret-with-adequate-entropy"
VERIFIER = "a" * 64
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")
CALLBACK = "http://127.0.0.1:17235/callback"


def invoke(coro):
    return asyncio.run(coro)


def request(method="GET", query="", form=None, origin=None):
    body = urlencode(form or {}).encode()
    headers = [(b"host", b"current.trycloudflare.com")]
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    if method == "POST":
        headers.extend([
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"content-length", str(len(body)).encode()),
        ])
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    return Request({
        "type": "http", "method": method,
        "scheme": "https", "path": "/oauth/consent", "root_path": "",
        "query_string": query.encode(), "headers": headers,
        "server": ("current.trycloudflare.com", 443),
        "client": ("127.0.0.1", 12345),
    }, receive=receive)


class OAuthProviderTests(unittest.TestCase):
    def setUp(self):
        self.provider = LocalConsentOAuthProvider(ISSUER, RESOURCE, OWNER_SECRET)
        self.client = OAuthClientInformationFull(
            client_id="client-1", client_name="A Test Client",
            redirect_uris=[CALLBACK], scope=READ_SCOPE,
            token_endpoint_auth_method="none",
        )
        self.params = AuthorizationParams(
            state="test-state", scopes=[READ_SCOPE], code_challenge=CHALLENGE,
            redirect_uri=AnyUrl(CALLBACK), redirect_uri_provided_explicitly=True,
            resource=RESOURCE,
        )
        invoke(self.provider.register_client(self.client))

    def _ticket(self):
        redirect = invoke(self.provider.authorize(self.client, self.params))
        self.assertEqual(urlsplit(redirect).path, "/oauth/consent")
        return parse_qs(urlsplit(redirect).query)["request_id"][0]

    def _approve(self, ticket):
        response = invoke(self.provider.consent(request(
            method="POST", origin=ISSUER,
            form={"request_id": ticket, "owner_token": OWNER_SECRET, "decision": "allow"},
        )))
        self.assertEqual(response.status_code, 303)
        return parse_qs(urlsplit(response.headers["location"]).query)["code"][0]

    def test_consent_is_required_and_password_not_in_html(self):
        ticket = self._ticket()
        self.assertEqual(len(self.provider.codes), 0)
        response = invoke(self.provider.consent(request(query=urlencode({"request_id": ticket}))))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(OWNER_SECRET, response.body.decode())
        self.assertIn("A Test Client", response.body.decode())
        self.assertIn("no-store", response.headers["cache-control"])

    def test_cross_origin_and_wrong_secret_rejected(self):
        ticket = self._ticket()
        denial = invoke(self.provider.consent(request(
            "POST", origin="https://evil.example.com",
            form={"request_id": ticket, "owner_token": OWNER_SECRET, "decision": "allow"},
        )))
        self.assertEqual(denial.status_code, 403)
        wrong = invoke(self.provider.consent(request(
            "POST", origin=ISSUER,
            form={"request_id": ticket, "owner_token": "wrong", "decision": "allow"},
        )))
        self.assertEqual(wrong.status_code, 403)
        self.assertFalse(self.provider.codes)

    def test_allow_issues_code_then_one_time_tokens(self):
        ticket = self._ticket()
        code = self._approve(ticket)
        self.assertNotIn(ticket, self.provider.pending)
        loaded = invoke(self.provider.load_authorization_code(self.client, code))
        self.assertEqual(loaded.code, code)
        self.assertEqual(loaded.resource, RESOURCE)
        tokens = invoke(self.provider.exchange_authorization_code(self.client, loaded))
        self.assertIsNotNone(tokens.refresh_token)
        self.assertNotIn(tokens.access_token, self.provider.access)
        access = invoke(self.provider.load_access_token(tokens.access_token))
        self.assertEqual(access.scopes, [READ_SCOPE])
        self.assertEqual(access.resource, RESOURCE)
        self.assertIsNone(invoke(self.provider.load_authorization_code(self.client, code)))
        with self.assertRaises(TokenError):
            invoke(self.provider.exchange_authorization_code(self.client, loaded))

    def test_refresh_rotates_and_revoke_clears_family(self):
        code = self._approve(self._ticket())
        auth_code = invoke(self.provider.load_authorization_code(self.client, code))
        t1 = invoke(self.provider.exchange_authorization_code(self.client, auth_code))
        refresh = invoke(self.provider.load_refresh_token(self.client, t1.refresh_token))
        t2 = invoke(self.provider.exchange_refresh_token(self.client, refresh, [READ_SCOPE]))
        self.assertIsNone(invoke(self.provider.load_access_token(t1.access_token)))
        self.assertIsNone(invoke(self.provider.load_refresh_token(self.client, t1.refresh_token)))
        current = invoke(self.provider.load_access_token(t2.access_token))
        invoke(self.provider.revoke_token(current))
        self.assertIsNone(invoke(self.provider.load_access_token(t2.access_token)))
        self.assertIsNone(invoke(self.provider.load_refresh_token(self.client, t2.refresh_token)))

    def test_resource_and_scope_restrictions(self):
        self.params.resource = "https://different.trycloudflare.com/mcp"
        with self.assertRaises(AuthorizeError):
            self._ticket()
        self.params.resource = RESOURCE
        self.params.scopes = ["cmd:exec"]
        with self.assertRaises(AuthorizeError):
            self._ticket()

    def test_old_quick_url_tokens_not_reusable(self):
        code = self._approve(self._ticket())
        auth_code = invoke(self.provider.load_authorization_code(self.client, code))
        tokens = invoke(self.provider.exchange_authorization_code(self.client, auth_code))
        replacement = LocalConsentOAuthProvider(
            "https://new.trycloudflare.com", "https://new.trycloudflare.com/mcp", OWNER_SECRET
        )
        self.assertIsNone(invoke(replacement.load_access_token(tokens.access_token)))
        self.assertIsNone(invoke(replacement.get_client(self.client.client_id)))

    def test_denial_does_not_issue_authorization_code(self):
        ticket = self._ticket()
        response = invoke(self.provider.consent(request(
            method="POST", origin=ISSUER, form={"request_id": ticket, "decision": "deny"}
        )))
        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            parse_qs(urlsplit(response.headers["location"]).query)["error"], ["access_denied"]
        )
        self.assertEqual(self.provider.codes, {})

    def test_owner_bearer_legacy_kept_with_read_only_scope(self):
        legacy = invoke(self.provider.load_access_token(OWNER_SECRET))
        self.assertEqual(legacy.scopes, [READ_SCOPE])
        self.assertEqual(legacy.client_id, "mcp-app-user")
        self.assertEqual(legacy.resource, RESOURCE)

    def test_dcr_capacity_bound(self):
        for i in range(MAX_CLIENTS - 1):
            client = self.client.model_copy(update={"client_id": f"client-{i+2}"})
            invoke(self.provider.register_client(client))
        with self.assertRaises(RegistrationError):
            invoke(self.provider.register_client(self.client.model_copy(update={"client_id": "overflow"})))


if __name__ == "__main__":
    unittest.main()
