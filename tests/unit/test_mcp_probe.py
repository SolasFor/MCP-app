"""Unit-тесты tools/mcp_probe.py: только чистые функции, без сети и без моков сервера."""
from __future__ import annotations

import sys
from email.message import Message
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import mcp_probe as p  # noqa: E402


def _resp(status: int | None, body: bytes = b"", **headers: str) -> p.Response:
    msg = Message()
    for k, v in headers.items():
        msg[k.replace("_", "-")] = v
    return p.Response(status, msg, body, 0)


def test_parse_json_object_and_batch() -> None:
    msgs, err = p.parse_jsonrpc("application/json", b'{"jsonrpc":"2.0","id":1,"result":{}}')
    assert err == "" and msgs[0]["id"] == 1
    msgs, _ = p.parse_jsonrpc("application/json", b'[{"id":1,"result":{}},{"id":2,"result":{}}]')
    assert [m["id"] for m in msgs] == [1, 2]


def test_parse_sse_multiline_and_single_space_strip() -> None:
    body = b'event: message\ndata: {"jsonrpc":"2.0",\ndata:  "id":7,"result":{}}\n\n'
    msgs, err = p.parse_jsonrpc("text/event-stream", body)
    assert err == ""
    assert p.find_response(msgs, 7) is not None


def test_parse_rejects_html() -> None:
    msgs, err = p.parse_jsonrpc("text/html", b"<html></html>")
    assert msgs == [] and "text/html" in err


def test_find_response_ignores_notifications_and_other_ids() -> None:
    msgs = [{"method": "notifications/progress"}, {"id": 2, "result": {}}]
    assert p.find_response(msgs, 1) is None
    assert p.find_response(msgs, 2) == {"id": 2, "result": {}}


def test_as_metadata_urls_root_issuer() -> None:
    assert p.as_metadata_urls("https://a.trycloudflare.com/") == [
        "https://a.trycloudflare.com/.well-known/oauth-authorization-server",
        "https://a.trycloudflare.com/.well-known/openid-configuration",
    ]


def test_as_metadata_urls_issuer_with_path() -> None:
    assert p.as_metadata_urls("https://auth.example.com/tenant1") == [
        "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
        "https://auth.example.com/.well-known/openid-configuration/tenant1",
        "https://auth.example.com/tenant1/.well-known/openid-configuration",
    ]


def test_prm_url_uses_resource_path() -> None:
    assert p.prm_url("https://a.trycloudflare.com/mcp") == (
        "https://a.trycloudflare.com/.well-known/oauth-protected-resource/mcp"
    )


def test_same_url_tolerates_case_and_trailing_slash_only() -> None:
    assert p.same_url("https://A.trycloudflare.com/mcp/", "https://a.trycloudflare.com/mcp")
    assert not p.same_url("https://old.trycloudflare.com/mcp", "https://new.trycloudflare.com/mcp")
    assert not p.same_url("https://a.trycloudflare.com/mcp", "https://a.trycloudflare.com/other")


def test_is_quick_tunnel() -> None:
    assert p.is_quick_tunnel("https://x-y.trycloudflare.com/mcp")
    assert not p.is_quick_tunnel("https://mcp.example.com/mcp")
    assert not p.is_quick_tunnel("https://trycloudflare.com.evil.example/mcp")


def test_classify_cloudflare_origin_error() -> None:
    code, _, _ = p.classify_failure(_resp(530, b"error 1033 cloudflare tunnel", Server="cloudflare"))
    assert code == "CF_ORIGIN"


def test_classify_host_rejected_and_redirect_and_network() -> None:
    assert p.classify_failure(_resp(421))[0] == "HOST_REJECTED"
    assert p.classify_failure(_resp(307, Location="https://x/"))[0] == "REDIRECT"
    assert p.classify_failure(p.Response(None, None, b"", 0, "refused"))[0] == "NETWORK"
    assert p.classify_failure(p.Response(None, None, b"", 0, "t", True))[0] == "TIMEOUT"


def test_redact_and_mask_never_leak_token() -> None:
    token = "s3cr3t-token-value"
    assert token not in p.redact(f"Authorization: Bearer {token}", token)
    assert token not in p.mask(token)
