"""Автоматическая настройка «своего домена» через API Cloudflare.

От пользователя — токен API (первый токен можно создать только в панели) и имя
хоста. Дальше setup_domain():

  1. находит зону и аккаунт по имени хоста          GET  /zones?name=…
  2. создаёт туннель (или берёт свой прошлый)         POST /accounts/{a}/cfd_tunnel
  3. пишет ingress: hostname → http://127.0.0.1:<порт>    PUT  …/cfd_tunnel/{t}/configurations
  4. создаёт CNAME <host> → <uuid>.cfargotunnel.com       POST /zones/{z}/dns_records
  5. получает токен туннеля для `cloudflared tunnel run`  GET  …/cfd_tunnel/{t}/token

Повторный запуск безопасен: туннель ищется по имени, CNAME на старый туннель
переписывается. Чужие записи (A, CNAME не на cfargotunnel.com) не трогаем — сообщаем.

Запросы идут через proxy.https_request: если api.cloudflare.com в списке вкладки
«Прокси», — через прокси. Токен API нигде не сохраняется: после настройки нужен
только токен туннеля (см. app/core/domain_state.py).
Вызывать из фонового потока: все запросы блокирующие.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit

from app.core import proxy as px

API = "https://api.cloudflare.com/client/v4"
TOKEN_PERMISSIONS = (
    "Account › Cloudflare Tunnel › Edit",
    "Zone › DNS › Edit",
    "Zone › Zone › Read",
)
SETUP_STEPS = (
    "Нахожу домен в аккаунте Cloudflare",
    "Создаю туннель",
    "Направляю адрес на этот компьютер",
    "Создаю DNS-запись",
    "Получаю ключ туннеля",
)
TUNNEL_SUFFIX = ".cfargotunnel.com"
_HOST_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


class CloudflareError(Exception):
    """Ошибка с понятным пользователю текстом."""


@dataclass(frozen=True)
class DomainResult:
    hostname: str
    zone_name: str
    account_id: str
    tunnel_id: str
    tunnel_token: str


def normalize_hostname(text: str) -> str:
    """«https://mcp.example.com/mcp», «MCP.example.com.» → «mcp.example.com» (IDN → punycode)."""
    value = text.strip().lower()
    if "://" in value:
        value = urlsplit(value).hostname or ""
    value = value.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        value = ""
    if not _HOST_RE.match(value):
        raise CloudflareError("Введите адрес вида mcp.example.com — поддомен домена, добавленного в Cloudflare")
    return value


def tunnel_name(hostname: str) -> str:
    return "mcp-app-" + re.sub(r"[^a-z0-9-]", "-", hostname)


def _explain(status: int, errors: list[dict[str, Any]]) -> str:
    codes = {e.get("code") for e in errors}
    if status in (401, 403) or codes & {9109, 10000, 10001}:
        return ("Cloudflare не принял токен или ему не хватает прав. Нужны: "
                + ", ".join(TOKEN_PERMISSIONS) + "; в Zone Resources — ваш домен.")
    messages = "; ".join(f"[{e.get('code')}] {e.get('message')}" for e in errors)
    return f"Cloudflare вернул ошибку (HTTP {status}): {messages or 'без подробностей'}"


class CloudflareAPI:
    def __init__(self, api_token: str, proxy_settings: px.ProxySettings | None = None,
                 timeout: float = 20.0) -> None:
        token = api_token.strip()
        if not token:
            raise CloudflareError("Вставьте токен API Cloudflare")
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "MCP-app",
        }
        self._proxy = proxy_settings or px.ProxySettings()
        self._timeout = timeout

    def call(self, method: str, path: str, payload: Any = None, params: dict[str, str] | None = None) -> Any:
        url = API + path + (f"?{urlencode(params)}" if params else "")
        body = json.dumps(payload).encode() if payload is not None else None
        status, _headers, data = px.https_request(self._proxy, method, url, dict(self._headers), body, self._timeout)
        try:
            doc = json.loads(data or b"{}")
        except ValueError:
            raise CloudflareError(f"Cloudflare ответил не JSON (HTTP {status})") from None
        if status >= 400 or not doc.get("success", False):
            raise CloudflareError(_explain(status, doc.get("errors") or []))
        return doc.get("result")

    # --------------------------------------------------------------- шаги
    def find_zone(self, hostname: str) -> tuple[str, str, str]:
        """(zone_id, zone_name, account_id): самая длинная активная зона, в которую входит хост."""
        labels = hostname.split(".")
        for i in range(len(labels) - 1):
            zones = self.call("GET", "/zones", params={"name": ".".join(labels[i:]), "status": "active"}) or []
            if zones:
                zone = zones[0]
                return zone["id"], zone["name"], zone["account"]["id"]
        raise CloudflareError(
            f"Домен для {hostname} не найден среди активных зон. Добавьте домен в Cloudflare "
            "и дождитесь статуса Active (NS-записи у регистратора) или дайте токену доступ к этой зоне.")

    def find_tunnel(self, account_id: str, name: str) -> str | None:
        tunnels = self.call("GET", f"/accounts/{account_id}/cfd_tunnel",
                            params={"name": name, "is_deleted": "false"}) or []
        return tunnels[0]["id"] if tunnels else None

    def create_tunnel(self, account_id: str, name: str) -> str:
        result = self.call("POST", f"/accounts/{account_id}/cfd_tunnel",
                           {"name": name, "config_src": "cloudflare"})
        return result["id"]

    def put_ingress(self, account_id: str, tunnel_id: str, hostname: str, service: str) -> None:
        self.call("PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations", {
            "config": {"ingress": [
                {"hostname": hostname, "service": service},
                {"service": "http_status:404"},
            ]},
        })

    def upsert_cname(self, zone_id: str, hostname: str, tunnel_id: str) -> None:
        target = tunnel_id + TUNNEL_SUFFIX
        record = {"type": "CNAME", "name": hostname, "content": target, "proxied": True, "ttl": 1,
                  "comment": "MCP app"}
        existing = self.call("GET", f"/zones/{zone_id}/dns_records", params={"name": hostname}) or []
        for item in existing:
            if item.get("type") == "CNAME" and str(item.get("content", "")).endswith(TUNNEL_SUFFIX):
                if item.get("content") != target or not item.get("proxied"):
                    self.call("PATCH", f"/zones/{zone_id}/dns_records/{item['id']}", record)
                return
        if existing:
            kinds = ", ".join(sorted({str(item.get("type", "?")) for item in existing}))
            raise CloudflareError(
                f"Для {hostname} уже есть DNS-записи ({kinds}), не связанные с туннелем. "
                "Удалите их в панели Cloudflare или выберите другой адрес.")
        self.call("POST", f"/zones/{zone_id}/dns_records", record)

    def tunnel_token(self, account_id: str, tunnel_id: str) -> str:
        token = self.call("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token")
        if not isinstance(token, str) or not token:
            raise CloudflareError("Cloudflare не вернул токен туннеля")
        return token


def setup_domain(api: CloudflareAPI, hostname: str, local_port: int,
                 on_step: Callable[[int], None] | None = None) -> DomainResult:
    """Все шаги SETUP_STEPS по порядку; on_step(i) — перед шагом i."""
    step = on_step or (lambda _index: None)
    host = normalize_hostname(hostname)

    step(0)
    zone_id, zone_name, account_id = api.find_zone(host)
    step(1)
    name = tunnel_name(host)
    tunnel_id = api.find_tunnel(account_id, name) or api.create_tunnel(account_id, name)
    step(2)
    api.put_ingress(account_id, tunnel_id, host, f"http://127.0.0.1:{int(local_port)}")
    step(3)
    api.upsert_cname(zone_id, host, tunnel_id)
    step(4)
    token = api.tunnel_token(account_id, tunnel_id)
    return DomainResult(host, zone_name, account_id, tunnel_id, token)
