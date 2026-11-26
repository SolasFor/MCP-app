"""Co-hosted OAuth 2.1 authorization provider for MCP-app.

The official MCP SDK implements DCR, redirect URI validation, PKCE S256,
authorization-code exchange, refresh handling, and OAuth metadata. This module
implements *only* the storage/consent hooks and consent UI/redirect handling.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from app.core.logging_manager import get_logging_manager

try:
    from .oauth_store import OAuthStore, canonical_oauth_urls
except ImportError:
    from oauth_store import OAuthStore, canonical_oauth_urls

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

READ_SCOPE = "mcp:read"
CODE_SECONDS = 300
ACCESS_SECONDS = 3600
REFRESH_SECONDS = 7 * 24 * 3600
MAX_CLIENTS = 128
MAX_PENDING = 64
MAX_FORM_BYTES = 4096
CSRF_COOKIE_NAME = "mcp_oauth_csrf"

_FORBIDDEN_REDIRECT_SCHEMES = frozenset({"javascript", "data", "vbscript", "blob", "file", "about"})

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    # no-referrer makes Origin: null on same-origin HTML form POST in browsers.
    # same-origin retains the correct Origin for consent POST, while preventing
    # Referer disclosure to the OAuth client's cross-origin redirect URI.
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    ),
}

_OAUTH_TEXT: dict[str, dict[str, str]] = {
    "ru": {
        "page_title": "MCP-app — Авторизация подключения",
        "heading": "Авторизация подключения",
        "subtitle": "{client} запрашивает доступ к вашему MCP-серверу.",
        "client_label": "Подключаемый клиент",
        "server_label": "Адрес MCP-сервера",
        "return_label": "Адрес возврата",
        "scenario_label": "Сценарий доступа",
        "mode_safe_title": "Безопасный режим",
        "mode_safe_desc": "Только чтение состояния и диагностика без выполнения команд.",
        "mode_allowlist_title": "Белый список",
        "mode_allowlist_desc": "Выполнение только разрешённых владельцем команд.",
        "mode_full_title": "Полный доступ",
        "mode_full_desc": "Произвольные команды CMD, PowerShell и SSH с правами текущей учётной записи.",
        "full_risk_warning": (
            "Высокий риск: клиент сможет выполнять произвольные команды и скрипты "
            "от имени вашего пользователя Windows без подтверждения каждого вызова."
        ),
        "token_label": "Токен владельца",
        "token_placeholder": "Введите ваш MCP-токен",
        "token_hint": "Токен доступен в настройках MCP-app.",
        "trust_notice": "Разрешайте доступ только доверенным приложениям. Вы сможете отозвать его в любое время.",
        "allow_btn": "Разрешить доступ",
        "deny_btn": "Отклонить",
        "footer": "MCP-app · Безопасное подключение OAuth",
        "err_bad_token_retry": "Неверный токен владельца MCP-app (осталось попыток: {remaining}).",
        "err_expired_title": "Запрос авторизации истёк",
        "err_expired_heading": "Запрос авторизации истёк",
        "err_expired_msg": "Эта ссылка авторизации устарела, уже использовалась или MCP-сервер был перезапущен.",
        "err_expired_hint": "Вернитесь в ваш AI-клиент и нажмите «Переподключить» (Reconnect), чтобы начать авторизацию заново.",
        "err_origin_title": "Ошибка проверки безопасности",
        "err_origin_heading": "Проверка безопасности не пройдена (Origin)",
        "err_origin_msg": "Форма авторизации отклонила запрос, так как заголовок Origin не совпадает с активным MCP-сервером.",
        "err_origin_hint": "Ожидаемый источник: {origin}. Запустите подключение повторно из AI-клиента.",
        "err_csrf_site_title": "Ошибка проверки безопасности",
        "err_csrf_site_heading": "Межсайтовая отправка формы заблокирована",
        "err_csrf_site_msg": "Заголовок безопасности браузера Sec-Fetch-Site указывает на внешний источник запроса.",
        "err_form_title": "Некорректный запрос",
        "err_form_heading": "Ошибка данных формы",
        "err_form_msg": "Не удалось прочитать отправленные данные формы авторизации.",
        "err_csrf_title": "Некорректный запрос",
        "err_csrf_heading": "Ошибка маркера безопасности (CSRF)",
        "err_csrf_msg": "Маркер сессии формы авторизации не совпадает. Обновите страницу или начните подключение заново.",
        "err_decision_title": "Некорректный запрос",
        "err_decision_heading": "Неизвестное действие",
        "err_decision_msg": "Передан недопустимый вариант подтверждения доступа.",
        "err_revoked_title": "Доступ клиента отозван",
        "err_revoked_heading": "Регистрация клиента отозвана",
        "err_revoked_msg": "Этот клиент был отозван в MCP-app и больше не может запрашивать токены.",
        "err_revoked_hint": "Переподключите сервер в вашем AI-клиенте, чтобы выполнить регистрацию заново.",
        "err_attempts_title": "Превышено число попыток",
        "err_attempts_heading": "Токен введён неверно",
        "err_attempts_msg": "Авторизация отменена после 5 неверных попыток ввода токена владельца.",
        "err_attempts_hint": "Проверьте токен владельца во вкладке «Подключение» в MCP-app и повторите подключение.",
        "err_authorize_title": "Ошибка авторизации",
        "err_authorize_heading": "Не удалось начать авторизацию ({code})",
        "err_authorize_hint_client": "Обычно это означает, что MCP-сервер перезапустился или сменил адрес после регистрации клиента. Нажмите «Переподключить» (Reconnect) в AI-клиенте.",
        "err_authorize_hint_generic": "Проверьте публичный адрес MCP-сервера и перезапустите подключение из вашего AI-клиента.",
    },
    "en": {
        "page_title": "MCP-app — Authorize Connection",
        "heading": "Authorize Connection",
        "subtitle": "{client} is requesting access to your MCP server.",
        "client_label": "Connecting client",
        "server_label": "MCP server URL",
        "return_label": "Return URL",
        "scenario_label": "Access scenario",
        "mode_safe_title": "Safe (Read-only)",
        "mode_safe_desc": "Read-only server info and diagnostics with no command execution.",
        "mode_allowlist_title": "Allowlist",
        "mode_allowlist_desc": "Executes only owner-approved commands and allowlisted tools.",
        "mode_full_title": "Full Access",
        "mode_full_desc": "Arbitrary CMD, PowerShell, and SSH commands under the current user account.",
        "full_risk_warning": (
            "High risk: this client can run arbitrary Windows and SSH commands with your user "
            "privileges immediately without per-command confirmation."
        ),
        "token_label": "Owner token",
        "token_placeholder": "Enter your MCP token",
        "token_hint": "Available in MCP-app → Connections.",
        "trust_notice": "Grant access only to trusted applications. You can revoke it at any time in MCP-app.",
        "allow_btn": "Allow access",
        "deny_btn": "Deny",
        "footer": "MCP-app · Secure OAuth Connection",
        "err_bad_token_retry": "Incorrect MCP Owner Token ({remaining} attempts remaining).",
        "err_expired_title": "Authorization expired",
        "err_expired_heading": "Authorization request expired",
        "err_expired_msg": "This authorization link has expired, was already used, or the MCP server restarted.",
        "err_expired_hint": "Return to your AI client and click Reconnect to start a fresh authorization.",
        "err_origin_title": "Invalid request",
        "err_origin_heading": "Security check failed (Origin)",
        "err_origin_msg": "This consent form rejected the request because its Origin header does not match the active MCP server.",
        "err_origin_hint": "Expected origin: {origin}. Restart authorization from your AI client.",
        "err_csrf_site_title": "Invalid request",
        "err_csrf_site_heading": "Cross-site form submission blocked",
        "err_csrf_site_msg": "Browser security header Sec-Fetch-Site indicated a cross-site submission.",
        "err_form_title": "Invalid request",
        "err_form_heading": "Invalid form submission",
        "err_form_msg": "The submitted form payload could not be decoded.",
        "err_csrf_title": "Invalid request",
        "err_csrf_heading": "Security token mismatch",
        "err_csrf_msg": "The consent form session token did not match. Reload the consent page or reconnect.",
        "err_decision_title": "Invalid request",
        "err_decision_heading": "Invalid decision",
        "err_decision_msg": "Unknown consent action.",
        "err_revoked_title": "Client revoked",
        "err_revoked_heading": "Client access revoked",
        "err_revoked_msg": "This client registration was revoked in MCP-app.",
        "err_revoked_hint": "Reconnect from your AI client to register a new OAuth client.",
        "err_attempts_title": "Too many attempts",
        "err_attempts_heading": "Owner token incorrect (attempts exhausted)",
        "err_attempts_msg": "Authorization cancelled after 5 incorrect attempts.",
        "err_attempts_hint": "Check the MCP Owner Token in Connections and restart authorization in your AI client.",
        "err_authorize_title": "Authorization failed",
        "err_authorize_heading": "Authorization failed ({code})",
        "err_authorize_hint_client": "This usually means the MCP server restarted or switched URL/provider after the client registered. Return to your AI client and click Reconnect to register and authorize cleanly.",
        "err_authorize_hint_generic": "Verify the server public URL and restart authorization from your AI client.",
    },
}


def resolve_oauth_language(
    request: Request | None = None,
    configured_lang: str | None = None,
) -> str:
    """Resolve UI language ('ru' or 'en') for OAuth browser pages.

    Order:
    1. Explicit ``?lang=ru|en`` query parameter if valid.
    2. Configured app language (``configured_lang`` or ``MCP_LANGUAGE`` env var).
    3. HTTP ``Accept-Language`` header preference.
    4. Default ``'en'`` when neither app language nor Accept-Language is supplied
       (preserves headless non-browser HTTP diagnostics), or ``'ru'`` for ru-* browsers.
    """
    if request is not None:
        qp_lang = (request.query_params.get("lang") or "").strip().lower()
        if qp_lang in ("ru", "en"):
            return qp_lang

    cfg = (configured_lang if configured_lang is not None else os.environ.get("MCP_LANGUAGE", "")).strip().lower()
    if cfg in ("ru", "en"):
        return cfg

    if request is not None:
        accept = (request.headers.get("accept-language") or "").strip().lower()
        if accept:
            ru_pos = accept.find("ru")
            en_pos = accept.find("en")
            if ru_pos >= 0 and (en_pos < 0 or ru_pos <= en_pos):
                return "ru"
            if en_pos >= 0:
                return "en"
    return "en"


def oauth_t(lang: str, key: str, **kwargs: object) -> str:
    table = _OAUTH_TEXT["ru" if lang == "ru" else "en"]
    text = table.get(key) or _OAUTH_TEXT["en"].get(key, key)
    return text.format(**kwargs) if kwargs else text


def _base_oauth_css() -> str:
    return """
  :root {
    color-scheme: dark light;
    --bg: #151617;
    --card: #202124;
    --card-border: #2E3136;
    --inset: #161719;
    --inset-border: #25282D;
    --emblem-bg: #161719;
    --emblem-border: #2B2E33;
    --text-strong: #F2F3F5;
    --text-body: #D2D5DB;
    --text-muted: #90959E;
    --text-faint: #6D727C;
    --divider: #2A2D32;
    --input-bg: #151618;
    --input-border: #32363D;
    --input-focus: #5E6AD2;
    --btn-primary: #5E6AD2;
    --btn-primary-hover: #6D79DE;
    --btn-primary-text: #FFFFFF;
    --btn-ghost-hover: rgba(255,255,255,0.06);
    --ok: #2EA043;
    --info: #58A6FF;
    --err: #E5534B;
    --err-bg: rgba(229,83,75,0.10);
    --err-border: rgba(229,83,75,0.38);
    --warn: #D97706;
    --warn-bg: rgba(217,119,6,0.11);
    --warn-border: rgba(217,119,6,0.42);
  }
  @media (prefers-color-scheme: light) {
    :root {
      --bg: #F5F6F8;
      --card: #FFFFFF;
      --card-border: #DFE2E7;
      --inset: #F4F5F7;
      --inset-border: #E4E7EC;
      --emblem-bg: #ECEEF2;
      --emblem-border: #DCE0E6;
      --text-strong: #161719;
      --text-body: #343841;
      --text-muted: #616670;
      --text-faint: #7E848F;
      --divider: #E6E8ED;
      --input-bg: #FFFFFF;
      --input-border: #CDD2DA;
      --input-focus: #4F5BD5;
      --btn-primary: #4F5BD5;
      --btn-primary-hover: #4450C7;
      --btn-primary-text: #FFFFFF;
      --btn-ghost-hover: rgba(22,23,25,0.05);
      --ok: #1A7F37;
      --info: #0969DA;
      --err: #CF222E;
      --err-bg: rgba(207,34,46,0.08);
      --err-border: rgba(207,34,46,0.32);
      --warn: #B45309;
      --warn-bg: rgba(180,83,9,0.08);
      --warn-border: rgba(180,83,9,0.34);
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 28px 16px;
    background: var(--bg);
    color: var(--text-body);
    font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, "Inter", sans-serif;
    font-size: 13.5px;
    line-height: 1.45;
  }
  main.card {
    width: 100%;
    max-width: 416px;
    background: var(--card);
    border: 1px solid var(--card-border);
    border-radius: 14px;
    padding: 26px 24px 20px;
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.22);
  }
  .brand {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    margin-bottom: 18px;
  }
  .emblem {
    width: 44px;
    height: 44px;
    border-radius: 11px;
    background: var(--emblem-bg);
    border: 1px solid var(--emblem-border);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-strong);
    margin-bottom: 10px;
  }
  .brand-name {
    font-size: 16px;
    font-weight: 600;
    color: var(--text-strong);
    letter-spacing: -0.01em;
    margin: 0 0 4px;
  }
  h1 {
    margin: 0 0 6px;
    font-size: 16.5px;
    font-weight: 600;
    color: var(--text-strong);
    letter-spacing: -0.01em;
  }
  .subtitle {
    margin: 0;
    color: var(--text-muted);
    font-size: 12.5px;
    line-height: 1.45;
  }
  .panel {
    background: var(--inset);
    border: 1px solid var(--inset-border);
    border-radius: 10px;
    padding: 13px 14px;
    margin-bottom: 16px;
  }
  .field-label {
    font-size: 11.5px;
    color: var(--text-muted);
    margin: 0 0 3px;
  }
  .client-name {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-strong);
    word-break: break-word;
  }
  .meta-list {
    margin-top: 8px;
    display: flex;
    flex-direction: column;
    gap: 5px;
  }
  .meta-row {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .meta-key {
    font-size: 11px;
    color: var(--text-faint);
  }
  .meta-val {
    font-family: "Cascadia Mono", "Consolas", ui-monospace, monospace;
    font-size: 11.5px;
    color: var(--text-body);
    word-break: break-all;
  }
  .sep {
    height: 1px;
    background: var(--divider);
    margin: 11px 0;
  }
  .scenario-row {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 13.5px;
    font-weight: 600;
    color: var(--text-strong);
    margin: 2px 0 4px;
  }
  .scenario-safe { color: var(--info); }
  .scenario-allowlist { color: var(--ok); }
  .scenario-full { color: var(--err); }
  .scenario-desc {
    margin: 0;
    font-size: 12.5px;
    color: var(--text-muted);
  }
  .callout-danger {
    margin-bottom: 14px;
    padding: 10px 12px;
    border-radius: 9px;
    border: 1px solid var(--err-border);
    background: var(--err-bg);
    color: var(--text-strong);
    font-size: 12px;
    display: flex;
    gap: 8px;
    align-items: flex-start;
  }
  .callout-danger svg { color: var(--err); flex-shrink: 0; margin-top: 1px; }
  .alert-err {
    margin-bottom: 14px;
    padding: 10px 12px;
    border-radius: 9px;
    border: 1px solid var(--err-border);
    background: var(--err-bg);
    color: var(--err);
    font-size: 12.5px;
    font-weight: 600;
  }
  label.tok-label {
    display: block;
    font-size: 12px;
    font-weight: 500;
    color: var(--text-body);
    margin-bottom: 7px;
  }
  input[type="password"] {
    width: 100%;
    height: 38px;
    padding: 0 14px;
    border-radius: 19px;
    border: 1px solid var(--input-border);
    background: var(--input-bg);
    color: var(--text-strong);
    font-size: 13px;
    outline: none;
  }
  input[type="password"]::placeholder {
    color: var(--text-faint);
  }
  input[type="password"]:focus {
    border-color: var(--input-focus);
  }
  .hint {
    margin: 6px 0 0;
    font-size: 11.5px;
    color: var(--text-muted);
  }
  .trust-box {
    margin: 14px 0 16px;
    padding: 10px 12px;
    border-radius: 9px;
    border: 1px solid var(--inset-border);
    background: transparent;
    display: flex;
    align-items: flex-start;
    gap: 9px;
    font-size: 11.5px;
    color: var(--text-muted);
    line-height: 1.45;
  }
  .trust-box svg { flex-shrink: 0; margin-top: 1px; color: var(--text-muted); }
  .actions {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  button[type="submit"] {
    width: 100%;
    border: 0;
    border-radius: 9px;
    font-size: 13.5px;
    font-weight: 600;
    font-family: inherit;
    cursor: default;
  }
  button[value="allow"] {
    height: 38px;
    background: var(--btn-primary);
    color: var(--btn-primary-text);
  }
  button[value="allow"]:hover {
    background: var(--btn-primary-hover);
  }
  button[value="deny"] {
    height: 32px;
    background: transparent;
    color: var(--text-muted);
    font-weight: 500;
    font-size: 12.5px;
  }
  button[value="deny"]:hover {
    background: var(--btn-ghost-hover);
    color: var(--text-strong);
  }
  .footer {
    margin-top: 14px;
    padding-top: 12px;
    border-top: 1px solid var(--divider);
    text-align: center;
    font-size: 11px;
    color: var(--text-faint);
  }
  .err-heading {
    margin: 0 0 8px;
    font-size: 17px;
    font-weight: 600;
    color: var(--err);
  }
  .err-msg {
    margin: 0 0 10px;
    color: var(--text-body);
    line-height: 1.5;
  }
"""


_SVG_HUB = (
    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<circle cx="12" cy="5" r="2.2"/><circle cx="6" cy="18" r="2.2"/><circle cx="18" cy="18" r="2.2"/>'
    '<path d="M12 7.2v4.3m0 0-4.8 4.6m4.8-4.6 4.8 4.6"/></svg>'
)
_SVG_SHIELD_CHECK = (
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3z"/>'
    '<path d="M9 12l2 2 4-4"/></svg>'
)
_SVG_SHIELD_OUTLINE = (
    '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3z"/></svg>'
)
_SVG_ALERT = (
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>'
    '<path d="M12 9v4m0 4h.01"/></svg>'
)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _canonical_origin(url: str) -> str:
    """Normalize HTTP/HTTPS origin (lowercased host, default ports stripped, IPv6 bracketed)."""
    raw = (url or "").strip()
    if not raw or raw.lower() == "null":
        return ""
    try:
        parts = urlsplit(raw)
    except ValueError:
        return ""
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return ""
    try:
        port = parts.port
    except ValueError:
        return ""
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    host_lit = f"[{host}]" if ":" in host else host
    netloc = f"{host_lit}:{port}" if port else host_lit
    return f"{scheme}://{netloc}"


def _form_action_source_for_redirect(redirect_uri: str | None) -> str:
    """Return a single safe CSP ``form-action`` source for a validated client ``redirect_uri``."""
    raw = str(redirect_uri or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
    except ValueError:
        return ""
    scheme = (parts.scheme or "").lower()
    if not scheme or scheme in _FORBIDDEN_REDIRECT_SCHEMES:
        return ""
    if scheme in ("http", "https"):
        return _canonical_origin(raw)
    # Native custom schemes (vscode://, cursor://, chatgpt://) require scheme-source form `scheme:` in CSP3.
    if scheme[0].isalpha() and all(ch.isalnum() or ch in "+-." for ch in scheme):
        return f"{scheme}:"
    return ""


def consent_security_headers(redirect_uri: str | None = None) -> dict[str, str]:
    """Build security headers, scoping ``form-action`` only to `'self'` and one client callback origin.

    Chromium browsers (Chrome, Edge, Electron) check ``form-action`` on 303 redirect targets after
    form POST. Without the client's validated callback origin here, Chromium blocks the OAuth callback.
    """
    headers = dict(SECURITY_HEADERS)
    extra = _form_action_source_for_redirect(redirect_uri)
    if extra:
        headers["Content-Security-Policy"] = (
            f"default-src 'none'; style-src 'unsafe-inline'; form-action 'self' {extra}; "
            "base-uri 'none'; frame-ancestors 'none'"
        )
    return headers


def _render_error_html(
    title: str,
    heading: str,
    message: str,
    *,
    hint: str = "",
    retry_form_html: str = "",
    lang: str = "en",
) -> str:
    safe_title = html.escape(title)
    safe_heading = html.escape(heading)
    safe_msg = html.escape(message)
    safe_lang = "ru" if lang == "ru" else "en"
    hint_block = f"<div class='trust-box'>{_SVG_SHIELD_OUTLINE}<span>{html.escape(hint)}</span></div>" if hint else ""
    footer_text = html.escape(oauth_t(safe_lang, "footer"))
    return f"""<!doctype html>
<html lang="{safe_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{safe_title}</title>
<style>{_base_oauth_css()}</style>
</head>
<body><main class="card">
  <div class="brand">
    <div class="emblem">{_SVG_HUB}</div>
    <div class="brand-name">MCP-app</div>
  </div>
  <h1 class="err-heading">{safe_heading}</h1>
  <p class="err-msg">{safe_msg}</p>
  {hint_block}
  {retry_form_html}
  <div class="footer">{footer_text}</div>
</main></body></html>"""


@dataclass
class PendingConsent:
    client: OAuthClientInformationFull
    params: AuthorizationParams
    expires_at: float
    attempts: int = 0
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(24))


class LocalConsentOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """No automatic approval: owner must type the owner token to consent.

    OAuth access/refresh tokens belong strictly to their registered client and access profile;
    bearer transport authentication can use an HTTP-safe transport secret distinct from Unicode
    or whitespace-containing owner consent passwords.
    """

    def __init__(
        self,
        issuer: str,
        resource_url: str,
        owner_secret: str,
        store_path: str | Path | None = None,
        default_profile: str | None = None,
        *,
        transport_secret: str | None = None,
        language: str | None = None,
    ) -> None:
        if not owner_secret:
            raise ValueError("owner_secret must not be empty")
        canon_issuer, canon_resource = canonical_oauth_urls(resource_url or issuer)
        if canon_issuer and (not issuer or canonical_oauth_urls(issuer)[0] == canon_issuer):
            self.issuer = canon_issuer
            self.resource_url = canon_resource
        else:
            self.issuer = issuer.rstrip("/")
            self.resource_url = resource_url.rstrip("/")
        self._canonical_issuer_origin = _canonical_origin(self.issuer)
        self._owner_secret = owner_secret
        self._transport_secret = transport_secret if transport_secret is not None else owner_secret
        self._configured_language = (language or "").strip().lower()
        self._default_profile = default_profile
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.pending: dict[str, PendingConsent] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.access: dict[str, AccessToken] = {}
        self.refresh: dict[str, RefreshToken] = {}
        self._families: dict[str, str] = {}
        self.store = OAuthStore(store_path, self.issuer, self.resource_url) if store_path else None
        if self.store:
            self.store.remove_old_quick_tunnels()
            self.store.bind_owner(owner_secret)
            self.store.prune_expired()

    def _lang_for_request(self, request: Request | None = None) -> str:
        return resolve_oauth_language(request, self._configured_language or None)

    @staticmethod
    def _log_oauth(level: str, event_code: str, message: str, *, req_id: str = "-") -> None:
        try:
            lm = get_logging_manager()
            lm.log("oauth", level, message, event_code=event_code, request_id=req_id)
        except Exception:  # noqa: BLE001
            pass

    def _cleanup(self) -> None:
        now = time.time()
        for data, expiry in (
            (self.pending, lambda x: x.expires_at),
            (self.codes, lambda x: x.expires_at),
            (self.access, lambda x: x.expires_at),
            (self.refresh, lambda x: x.expires_at),
        ):
            for key, value in list(data.items()):
                end = expiry(value)
                if end is not None and end < now:
                    del data[key]
                    self._families.pop(key, None)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.store.get_client(client_id) if self.store else self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if (self.store.count_clients() if self.store else len(self.clients)) >= MAX_CLIENTS:
            self._log_oauth("WARNING", "oauth_register_capacity", "DCR registration rejected: capacity reached")
            raise RegistrationError("invalid_client_metadata", "Registration capacity reached")
        if not client_info.client_id or client_info.client_id in self.clients:
            self._log_oauth("WARNING", "oauth_register_invalid_id", "DCR registration rejected: invalid client_id")
            raise RegistrationError("invalid_client_metadata", "Invalid client identifier")
        if self.store:
            self.store.save_client(client_info)
        else:
            self.clients[client_info.client_id] = client_info
        self._log_oauth(
            "INFO",
            "oauth_client_registered",
            f"Registered OAuth client_id={client_info.client_id} name={client_info.client_name or '-'}",
        )

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        self._cleanup()
        cid = client.client_id or ""
        if self.store and not self.store.get_client(cid):
            self._log_oauth("WARNING", "oauth_authorize_revoked", f"Authorize rejected for revoked client_id={cid}")
            raise AuthorizeError("unauthorized_client", "Client registration revoked")
        if params.resource is not None:
            raw_res = params.resource.rstrip("/")
            _, canon_res = canonical_oauth_urls(params.resource)
            if raw_res != self.resource_url and canon_res != self.resource_url:
                self._log_oauth(
                    "WARNING",
                    "oauth_resource_mismatch",
                    f"Authorize rejected: resource mismatch client_id={cid} requested={canon_res or raw_res} expected={self.resource_url}",
                )
                raise AuthorizeError("invalid_target", "The requested resource is not this MCP server")
        if params.scopes and set(params.scopes) != {READ_SCOPE}:
            self._log_oauth("WARNING", "oauth_invalid_scope", f"Authorize rejected: invalid scope client_id={cid}")
            raise AuthorizeError("invalid_scope", "Only the read-only MCP scope is available")
        if len(self.pending) >= MAX_PENDING:
            self._log_oauth("WARNING", "oauth_pending_limit", "Authorize rejected: too many pending authorization requests")
            raise AuthorizeError("temporarily_unavailable", "Too many pending authorization requests")
        ticket = secrets.token_urlsafe(32)
        req_prefix = token_digest(ticket)[:12]
        self.pending[token_digest(ticket)] = PendingConsent(
            client=client, params=params, expires_at=time.time() + CODE_SECONDS
        )
        self._log_oauth(
            "INFO",
            "oauth_consent_created",
            f"Created OAuth consent session client_id={cid} redirect_origin={_form_action_source_for_redirect(str(params.redirect_uri))}",
            req_id=req_prefix,
        )
        return f"{self.issuer}/oauth/consent?{urlencode({'request_id': ticket})}"

    def _code_for(self, pending: PendingConsent) -> str:
        assert pending.client.client_id
        code = secrets.token_urlsafe(32)
        self.codes[token_digest(code)] = AuthorizationCode(
            code=code,
            client_id=pending.client.client_id,
            scopes=[READ_SCOPE],
            expires_at=time.time() + CODE_SECONDS,
            code_challenge=pending.params.code_challenge,
            redirect_uri=pending.params.redirect_uri,
            redirect_uri_provided_explicitly=pending.params.redirect_uri_provided_explicitly,
            resource=self.resource_url,
            subject="local-owner",
        )
        return code

    def _consent_form_html(
        self,
        pending: PendingConsent,
        ticket: str,
        *,
        error_note: str = "",
        lang: str = "ru",
    ) -> str:
        safe_lang = "ru" if lang == "ru" else "en"
        raw_client = pending.client.client_name or pending.client.client_id or "MCP Client"
        display_name = html.escape(raw_client)
        display_server = html.escape(self.resource_url or self.issuer)
        display_uri = html.escape(str(pending.params.redirect_uri))
        safe_ticket = html.escape(ticket, quote=True)
        safe_csrf = html.escape(pending.csrf_token, quote=True)
        mode = self._default_profile or "safe"
        if self.store:
            try:
                from .oauth_execution import ExecutionApprovals
            except ImportError:
                from oauth_execution import ExecutionApprovals
            profiles = ExecutionApprovals(self.store, default_profile=self._default_profile)
            mode = (
                profiles.profile_for(pending.client.client_id)
                if profiles.client_approved(pending.client.client_id)
                else profiles.profile()
            )
        if mode not in ("safe", "allowlist", "full"):
            mode = "safe"

        mode_title = html.escape(oauth_t(safe_lang, f"mode_{mode}_title"))
        mode_desc = html.escape(oauth_t(safe_lang, f"mode_{mode}_desc"))
        mode_icon = _SVG_ALERT if mode == "full" else (_SVG_SHIELD_CHECK if mode == "allowlist" else _SVG_SHIELD_OUTLINE)
        mode_cls = f"scenario-{mode}"

        err_html = f"<div class='alert-err' role='alert'>{html.escape(error_note)}</div>" if error_note else ""
        full_warning_html = (
            f"<div class='callout-danger'>{_SVG_ALERT}<span>{html.escape(oauth_t(safe_lang, 'full_risk_warning'))}</span></div>"
            if mode == "full"
            else ""
        )

        return f"""<!doctype html>
<html lang="{safe_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(oauth_t(safe_lang, "page_title"))}</title>
<style>{_base_oauth_css()}</style>
</head>
<body>
<main class="card">
  <div class="brand">
    <div class="emblem">{_SVG_HUB}</div>
    <div class="brand-name">MCP-app</div>
    <h1>{html.escape(oauth_t(safe_lang, "heading"))}</h1>
    <p class="subtitle">{html.escape(oauth_t(safe_lang, "subtitle", client=raw_client))}</p>
  </div>
  {err_html}
  <section class="panel" aria-label="{html.escape(oauth_t(safe_lang, 'scenario_label'))}">
    <div class="field-label">{html.escape(oauth_t(safe_lang, "client_label"))}</div>
    <div class="client-name">{display_name}</div>
    <div class="meta-list">
      <div class="meta-row">
        <span class="meta-key">{html.escape(oauth_t(safe_lang, "server_label"))}</span>
        <span class="meta-val">{display_server}</span>
      </div>
      <div class="meta-row">
        <span class="meta-key">{html.escape(oauth_t(safe_lang, "return_label"))}</span>
        <span class="meta-val">{display_uri}</span>
      </div>
    </div>
    <div class="sep"></div>
    <div class="field-label">{html.escape(oauth_t(safe_lang, "scenario_label"))}</div>
    <div class="scenario-row {mode_cls}">{mode_icon}<span>{mode_title}</span></div>
    <p class="scenario-desc">{mode_desc}</p>
  </section>
  {full_warning_html}
  <form method="post" action="/oauth/consent">
    <input type="hidden" name="request_id" value="{safe_ticket}">
    <input type="hidden" name="csrf_token" value="{safe_csrf}">
    <label class="tok-label" for="owner_token">{html.escape(oauth_t(safe_lang, "token_label"))}</label>
    <input id="owner_token" type="password" name="owner_token" autocomplete="current-password" placeholder="{html.escape(oauth_t(safe_lang, 'token_placeholder'), quote=True)}" required autofocus>
    <p class="hint">{html.escape(oauth_t(safe_lang, "token_hint"))}</p>
    <div class="trust-box">
      {_SVG_SHIELD_OUTLINE}
      <span>{html.escape(oauth_t(safe_lang, "trust_notice"))}</span>
    </div>
    <div class="actions">
      <button type="submit" name="decision" value="allow">{html.escape(oauth_t(safe_lang, "allow_btn"))}</button>
      <button type="submit" name="decision" value="deny" formnovalidate>{html.escape(oauth_t(safe_lang, "deny_btn"))}</button>
    </div>
  </form>
  <div class="footer">{html.escape(oauth_t(safe_lang, "footer"))}</div>
</main>
</body>
</html>"""

    async def consent(self, request: Request) -> Response:
        """HTTP consent route registered through MCPServer.custom_route.

        No secret in URLs, cookies, HTML attributes or access logs. Dynamically allows only the
        single validated OAuth client ``redirect_uri`` in CSP ``form-action`` so Chromium browsers
        (Chrome/Edge) follow the cross-origin 303 redirect after consent form POST.
        """
        lang = self._lang_for_request(request)
        if request.method == "GET":
            ticket = request.query_params.get("request_id", "")
            req_prefix = token_digest(ticket)[:12] if ticket else "-"
            pending = self.pending.get(token_digest(ticket))
            self._cleanup()
            if not pending or pending.expires_at < time.time():
                self._log_oauth("WARNING", "oauth_consent_expired", "Consent GET rejected: expired or unknown request_id", req_id=req_prefix)
                expired_html = _render_error_html(
                    oauth_t(lang, "err_expired_title"),
                    oauth_t(lang, "err_expired_heading"),
                    oauth_t(lang, "err_expired_msg"),
                    hint=oauth_t(lang, "err_expired_hint"),
                    lang=lang,
                )
                return HTMLResponse(expired_html, status_code=410, headers=SECURITY_HEADERS)
            target_uri = str(pending.params.redirect_uri)
            headers = consent_security_headers(target_uri)
            resp = HTMLResponse(self._consent_form_html(pending, ticket, lang=lang), headers=headers)
            resp.set_cookie(
                CSRF_COOKIE_NAME,
                pending.csrf_token,
                max_age=CODE_SECONDS,
                path="/oauth/consent",
                httponly=True,
                samesite="lax",
                secure=self.issuer.startswith("https://") or request.url.scheme == "https",
            )
            return resp

        if request.method != "POST":
            return Response(status_code=405, headers=SECURITY_HEADERS)

        origin_hdr = request.headers.get("origin", "")
        canon_req_origin = _canonical_origin(origin_hdr)
        if not canon_req_origin or canon_req_origin != self._canonical_issuer_origin:
            self._log_oauth(
                "WARNING",
                "oauth_origin_rejected",
                f"Consent POST rejected: origin mismatch got={canon_req_origin or origin_hdr!r} expected={self._canonical_issuer_origin!r}",
            )
            err_html = _render_error_html(
                oauth_t(lang, "err_origin_title"),
                oauth_t(lang, "err_origin_heading"),
                oauth_t(lang, "err_origin_msg"),
                hint=oauth_t(lang, "err_origin_hint", origin=self._canonical_issuer_origin),
                lang=lang,
            )
            return HTMLResponse(err_html, status_code=403, headers=SECURITY_HEADERS)

        sec_fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
        if sec_fetch_site and sec_fetch_site not in ("same-origin", "none"):
            self._log_oauth(
                "WARNING",
                "oauth_fetch_site_rejected",
                f"Consent POST rejected: Sec-Fetch-Site={sec_fetch_site!r}",
            )
            err_html = _render_error_html(
                oauth_t(lang, "err_csrf_site_title"),
                oauth_t(lang, "err_csrf_site_heading"),
                oauth_t(lang, "err_csrf_site_msg"),
                lang=lang,
            )
            return HTMLResponse(err_html, status_code=403, headers=SECURITY_HEADERS)

        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/x-www-form-urlencoded":
            return Response(status_code=415, headers=SECURITY_HEADERS)
        if int(request.headers.get("content-length", "0") or "0") > MAX_FORM_BYTES:
            return Response(status_code=413, headers=SECURITY_HEADERS)
        body = await request.body()
        if len(body) > MAX_FORM_BYTES:
            return Response(status_code=413, headers=SECURITY_HEADERS)
        try:
            fields = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
        except (ValueError, UnicodeError):
            self._log_oauth("WARNING", "oauth_malformed_form", "Consent POST rejected: malformed form encoding")
            return HTMLResponse(
                _render_error_html(
                    oauth_t(lang, "err_form_title"),
                    oauth_t(lang, "err_form_heading"),
                    oauth_t(lang, "err_form_msg"),
                    lang=lang,
                ),
                status_code=400,
                headers=SECURITY_HEADERS,
            )

        ticket = (fields.get("request_id") or [""])[0]
        digest = token_digest(ticket)
        req_prefix = digest[:12] if ticket else "-"
        pending = self.pending.get(digest)
        self._cleanup()
        if not pending or pending.expires_at < time.time():
            self._log_oauth("WARNING", "oauth_consent_expired", "Consent POST rejected: expired or missing pending request", req_id=req_prefix)
            return HTMLResponse(
                _render_error_html(
                    oauth_t(lang, "err_expired_title"),
                    oauth_t(lang, "err_expired_heading"),
                    oauth_t(lang, "err_expired_msg"),
                    hint=oauth_t(lang, "err_expired_hint"),
                    lang=lang,
                ),
                status_code=410,
                headers=SECURITY_HEADERS,
            )

        target = str(pending.params.redirect_uri)
        resp_headers = consent_security_headers(target)

        # Double-submit / server-bound CSRF check whenever browser sends form field or cookie.
        form_csrf = (fields.get("csrf_token") or [""])[0]
        cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME, "")
        if form_csrf or cookie_csrf:
            valid_form = bool(form_csrf) and hmac.compare_digest(form_csrf, pending.csrf_token)
            valid_cookie = (not cookie_csrf) or hmac.compare_digest(cookie_csrf, pending.csrf_token)
            if not (valid_form and valid_cookie):
                self._log_oauth("WARNING", "oauth_csrf_rejected", "Consent POST rejected: CSRF mismatch", req_id=req_prefix)
                return HTMLResponse(
                    _render_error_html(
                        oauth_t(lang, "err_csrf_title"),
                        oauth_t(lang, "err_csrf_heading"),
                        oauth_t(lang, "err_csrf_msg"),
                        lang=lang,
                    ),
                    status_code=403,
                    headers=resp_headers,
                )

        decision = (fields.get("decision") or [""])[0]
        state = pending.params.state
        if decision == "deny":
            del self.pending[digest]
            self._log_oauth("INFO", "oauth_consent_denied", f"Owner denied client_id={pending.client.client_id}", req_id=req_prefix)
            return RedirectResponse(
                construct_redirect_uri(target, error="access_denied", state=state),
                status_code=303,
                headers=resp_headers,
            )
        if decision != "allow":
            return HTMLResponse(
                _render_error_html(
                    oauth_t(lang, "err_decision_title"),
                    oauth_t(lang, "err_decision_heading"),
                    oauth_t(lang, "err_decision_msg"),
                    lang=lang,
                ),
                status_code=400,
                headers=resp_headers,
            )
        if self.store and not self.store.get_client(pending.client.client_id or ""):
            del self.pending[digest]
            self._log_oauth("WARNING", "oauth_client_revoked", f"Consent POST rejected: client revoked client_id={pending.client.client_id}", req_id=req_prefix)
            return HTMLResponse(
                _render_error_html(
                    oauth_t(lang, "err_revoked_title"),
                    oauth_t(lang, "err_revoked_heading"),
                    oauth_t(lang, "err_revoked_msg"),
                    hint=oauth_t(lang, "err_revoked_hint"),
                    lang=lang,
                ),
                status_code=403,
                headers=resp_headers,
            )

        candidate = (fields.get("owner_token") or [""])[0]
        if not hmac.compare_digest(candidate.encode("utf-8"), self._owner_secret.encode("utf-8")):
            pending.attempts += 1
            remaining = max(0, 5 - pending.attempts)
            self._log_oauth(
                "WARNING",
                "oauth_bad_owner_token",
                f"Incorrect owner token entered for client_id={pending.client.client_id} remaining_attempts={remaining}",
                req_id=req_prefix,
            )
            if pending.attempts >= 5:
                del self.pending[digest]
                return HTMLResponse(
                    _render_error_html(
                        oauth_t(lang, "err_attempts_title"),
                        oauth_t(lang, "err_attempts_heading"),
                        oauth_t(lang, "err_attempts_msg"),
                        hint=oauth_t(lang, "err_attempts_hint"),
                        lang=lang,
                    ),
                    status_code=403,
                    headers=resp_headers,
                )
            retry_html = self._consent_form_html(
                pending,
                ticket,
                error_note=oauth_t(lang, "err_bad_token_retry", remaining=remaining),
                lang=lang,
            )
            return HTMLResponse(retry_html, status_code=403, headers=resp_headers)

        del self.pending[digest]
        code = self._code_for(pending)
        self._log_oauth(
            "INFO",
            "oauth_consent_approved",
            f"OAuth consent approved client_id={pending.client.client_id} redirect_origin={_form_action_source_for_redirect(target)}",
            req_id=req_prefix,
        )
        return RedirectResponse(
            construct_redirect_uri(target, code=code, state=state, iss=self.issuer),
            status_code=303,
            headers=resp_headers,
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        self._cleanup()
        value = self.codes.get(token_digest(authorization_code))
        return value if value and value.client_id == client.client_id else None

    def _issue_tokens(self, client_id: str, scopes: list[str], family: str) -> OAuthToken:
        now = int(time.time())
        raw_access = secrets.token_urlsafe(32)
        raw_refresh = secrets.token_urlsafe(32)
        akey = token_digest(raw_access)
        rkey = token_digest(raw_refresh)
        self.access[akey] = AccessToken(
            token=raw_access, client_id=client_id, scopes=scopes,
            expires_at=now + ACCESS_SECONDS, resource=self.resource_url, subject="local-owner",
        )
        self.refresh[rkey] = RefreshToken(
            token=raw_refresh, client_id=client_id, scopes=scopes,
            expires_at=now + REFRESH_SECONDS, resource=self.resource_url, subject="local-owner",
        )
        self._families[akey] = family
        self._families[rkey] = family
        if self.store:
            self.store.save_token(self.access[akey], "access", family)
            self.store.save_token(self.refresh[rkey], "refresh", family)
            self.store.mark_approved(client_id)
        return OAuthToken(
            access_token=raw_access, refresh_token=raw_refresh,
            expires_in=ACCESS_SECONDS, token_type="Bearer", scope=" ".join(scopes),
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        key = token_digest(authorization_code.code)
        original = self.codes.pop(key, None)
        if (
            not original or original.client_id != client.client_id
            or original.expires_at < time.time() or original != authorization_code
        ):
            self._log_oauth("WARNING", "oauth_code_exchange_failed", f"Code exchange failed client_id={client.client_id}")
            raise TokenError("invalid_grant", "Invalid or already used authorization code")
        if self.store and not self.store.get_client(client.client_id):
            self._log_oauth("WARNING", "oauth_code_exchange_revoked", f"Code exchange rejected for revoked client_id={client.client_id}")
            raise TokenError("invalid_grant", "Client registration revoked")
        self._log_oauth("INFO", "oauth_token_issued", f"Issued OAuth token via auth code client_id={client.client_id}")
        return self._issue_tokens(client.client_id, original.scopes, secrets.token_urlsafe(16))

    async def load_access_token(self, token: str) -> AccessToken | None:
        if hmac.compare_digest(token.encode("utf-8"), self._transport_secret.encode("utf-8")):
            return AccessToken(
                token=token, client_id="mcp-app-user", scopes=[READ_SCOPE],
                resource=self.resource_url, subject="local-owner",
            )
        self._cleanup()
        if self.store:
            return self.store.get_token(token, "access")
        return self.access.get(token_digest(token))

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        self._cleanup()
        value = (
            self.store.get_token(refresh_token, "refresh")
            if self.store else self.refresh.get(token_digest(refresh_token))
        )
        return value if value and value.client_id == client.client_id else None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        key = token_digest(refresh_token.token)
        original = self.store.get_token(refresh_token.token, "refresh") if self.store else self.refresh.get(key)
        if (
            not original or original != refresh_token or original.client_id != client.client_id
            or original.expires_at is not None and original.expires_at < time.time()
        ):
            self._log_oauth("WARNING", "oauth_refresh_failed", f"Refresh token rejected client_id={client.client_id}")
            raise TokenError("invalid_grant", "Refresh token expired or already used")
        if not set(scopes).issubset(set(original.scopes)):
            raise TokenError("invalid_scope", "Cannot elevate token permissions")
        family = (
            self.store.consume_refresh(refresh_token.token, client.client_id)
            if self.store else self._families.get(key, "")
        )
        if not family:
            self._log_oauth("WARNING", "oauth_refresh_family_missing", f"Refresh family missing client_id={client.client_id}")
            raise TokenError("invalid_grant", "Token family not found")
        self._remove_family(family)
        if self.store and not self.store.get_client(client.client_id):
            raise TokenError("invalid_grant", "Client registration revoked")
        self._log_oauth("INFO", "oauth_token_refreshed", f"Refreshed OAuth token client_id={client.client_id}")
        return self._issue_tokens(client.client_id, scopes, family)

    def _remove_family(self, family: str) -> None:
        if self.store:
            self.store.revoke_family(family)
        for key, value in list(self._families.items()):
            if value == family:
                self.access.pop(key, None)
                self.refresh.pop(key, None)
                del self._families[key]

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        family = self.store.family(token.token) if self.store else self._families.get(token_digest(token.token))
        if family:
            self._remove_family(family)
            self._log_oauth("INFO", "oauth_token_revoked", f"Revoked OAuth token family={family[:8]}")
