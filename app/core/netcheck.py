"""Диагностика сети для временного адреса (quick tunnel).

cloudflared получает временный адрес запросом POST https://api.trycloudflare.com/tunnel.
Этот запрос идёт напрямую (http.Transport без Proxy: системный прокси и HTTPS_PROXY
не используются) и с жёстким таймаутом 15 с — см. cloudflared,
cmd/cloudflared/tunnel/quick_tunnel.go. Когда он не проходит, в журнале остаётся
только «context deadline exceeded», из которого не понять, что делать.

Здесь та же дорога проверяется по шагам: DNS -> TCP 443 -> TLS -> HTTP, плюс порт
7844, по которому туннель потом держит связь с Cloudflare. Итог — где именно она
обрывается и что с этим делать.

Только стандартная библиотека и без Qt: функция блокирующая (в худшем случае
десятки секунд), ServiceManager вызывает её в фоновом потоке.
"""
from __future__ import annotations

import socket
import ssl
import time
import urllib.request
from dataclasses import dataclass, field

QUICK_API_HOST = "api.trycloudflare.com"
EDGE_HOST = "region1.v2.argotunnel.com"  # сюда cloudflared подключается после выдачи адреса
EDGE_PORT = 7844
STEP_TIMEOUT_S = 6.0


@dataclass
class Diagnosis:
    reachable: bool  # False: повторять запуск бессмысленно, пока не починят сеть
    summary: str     # одна строка для журнала
    advice: list[str] = field(default_factory=list)


def system_proxy() -> str:
    """Прокси из настроек Windows или переменных окружения ('' — нет)."""
    try:
        proxies = urllib.request.getproxies()
    except Exception:  # noqa: BLE001 — битый реестр не должен ломать диагностику
        return ""
    return proxies.get("https") or proxies.get("http") or ""


def _reason(exc: BaseException, timeout: float) -> str:
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return f"нет ответа за {timeout:.0f} с"
    if isinstance(exc, ssl.SSLError):
        return f"ошибка TLS: {exc.reason or exc}"
    if isinstance(exc, ConnectionRefusedError):
        return "соединение отклонено"
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError)):
        return "соединение сброшено"
    return getattr(exc, "strerror", None) or str(exc) or type(exc).__name__


def _connect(host: str, port: int, timeout: float) -> tuple[socket.socket | None, str]:
    """TCP-соединение: (сокет, '') или (None, причина). IPv4 пробуем первым."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return None, f"DNS: {_reason(exc, timeout)}"
    addresses = sorted({info[4][0] for info in infos}, key=lambda ip: ":" in ip)
    errors = []
    for ip in addresses[:2]:
        try:
            return socket.create_connection((ip, port), timeout=timeout), ""
        except OSError as exc:
            errors.append(f"{ip}: {_reason(exc, timeout)}")
    return None, "; ".join(errors) or "нет адресов"


def _edge_open(timeout: float) -> tuple[bool, str]:
    sock, why = _connect(EDGE_HOST, EDGE_PORT, timeout)
    if sock is None:
        return False, why
    sock.close()
    return True, ""


def diagnose_quick_tunnel(timeout: float = STEP_TIMEOUT_S) -> Diagnosis:
    """Почему cloudflared не получил временный адрес. Блокирующая."""
    proxy = system_proxy()
    proxy_tip = (
        [f"В Windows задан прокси {proxy}. cloudflared через прокси не работает: нужен прямой выход "
         "в интернет или VPN в режиме «весь трафик» (TUN), а не только системный прокси."]
        if proxy else []
    )
    other_network = "Проверьте в другой сети — например, раздайте интернет с телефона."
    domain_tip = ("Если временный адрес в этой сети недоступен, подключите свой домен: "
                  "«Подключение» → «Как подключить свой домен».")

    # 1. DNS
    try:
        socket.getaddrinfo(QUICK_API_HOST, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        return Diagnosis(False, f"Компьютер не находит {QUICK_API_HOST} (DNS: {_reason(exc, timeout)}).", [
            "Проверьте, что интернет вообще есть: откройте любой сайт в браузере.",
            "Если сайты открываются — укажите DNS 1.1.1.1 или 8.8.8.8 в настройках сетевого адаптера.",
            *proxy_tip,
        ])

    # 2. TCP 443
    sock, why = _connect(QUICK_API_HOST, 443, timeout)
    if sock is None:
        edge_ok, _ = _edge_open(timeout)
        tips = ["Брандмауэр, антивирус или сама сеть (провайдер, офис, гостиница) не пускают к Cloudflare.",
                other_network, *proxy_tip]
        if edge_ok:
            tips.append(domain_tip)
        return Diagnosis(False, f"Нет соединения с {QUICK_API_HOST}:443 ({why}).", tips)

    # 3. TLS и 4. HTTP. Проверяем только проходимость, поэтому сертификат не сверяем:
    # на свежей Windows в хранилище, которое видит Python, может ещё не быть нужного
    # корневого сертификата (Windows докачивает их по запросу), а cloudflared это не мешает.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    stage = "tls"
    started = time.monotonic()
    try:
        with sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=QUICK_API_HOST) as tls:
                stage = "http"
                tls.sendall(
                    f"GET / HTTP/1.1\r\nHost: {QUICK_API_HOST}\r\nUser-Agent: MCPApp-netcheck\r\n"
                    "Connection: close\r\n\r\n".encode()
                )
                head = tls.recv(16)
        if not head.startswith(b"HTTP/"):
            raise ConnectionResetError("пустой ответ")
    except OSError as exc:
        reason = _reason(exc, timeout)
        if stage == "tls":
            return Diagnosis(False, (
                f"Соединение с {QUICK_API_HOST} открывается, но защищённое (TLS) не устанавливается ({reason}). "
                "Так выглядит блокировка или замедление Cloudflare со стороны сети или провайдера."
            ), [other_network, "VPN в режиме «весь трафик» обычно обходит такую блокировку.", *proxy_tip])
        return Diagnosis(False, (
            f"{QUICK_API_HOST} не отвечает на запросы ({reason}): связь обрывается уже после соединения. "
            "Похоже на фильтрацию трафика в сети."
        ), [other_network, "VPN в режиме «весь трафик» обычно обходит такую блокировку.", *proxy_tip])
    elapsed = time.monotonic() - started

    # 5. Порт 7844: без него туннель не подключится, даже получив адрес.
    edge_ok, edge_why = _edge_open(timeout)
    if not edge_ok:
        return Diagnosis(False, (
            f"{QUICK_API_HOST} отвечает, но порт {EDGE_PORT} Cloudflare ({EDGE_HOST}) закрыт: {edge_why}. "
            "По нему туннель держит связь — без него не заработает ни временный адрес, ни свой домен."
        ), [f"Разрешите исходящие соединения на порт {EDGE_PORT} (TCP и UDP) в брандмауэре или роутере.",
            other_network, *proxy_tip])

    return Diagnosis(True, (
        f"Связь с Cloudflare есть ({QUICK_API_HOST} ответил за {elapsed:.1f} с, порт {EDGE_PORT} открыт), "
        "но cloudflared адрес не получил."
    ), [
        "Сервис trycloudflare.com иногда перегружен или ограничивает выдачу — приложение повторит попытки.",
        "Если не поможет: проверьте, не блокирует ли антивирус или брандмауэр сам cloudflared.exe, "
        "либо подключите свой домен.",
    ])
