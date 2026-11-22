"""Оркестратор: единственная точка, с которой разговаривает GUI.

    GUI ──start_all()/stop_all()──▶ ServiceManager ──▶ ManagedProcess("server")
    GUI ◀─────── сигналы ──────── ServiceManager ──▶ ManagedProcess("tunnel")
                                         │
                                         ├──▶ HealthMonitor (GET :8000/health, /ready)
                                         └──▶ ProxyBridge (мосты cloudflared → прокси, app/core/edge_relay.py)

Два режима туннеля:

* quick (временный *.trycloudflare.com, по умолчанию): preflight -> tunnel -> (cloudflared
  напечатал адрес) -> server. Серверу нужен свой публичный адрес
  (resource_server_url для OAuth-метаданных и проверки токена), а он появляется
  только после старта туннеля. Если cloudflared перезапустится и выдаст новый
  адрес — сервер перезапускается с ним.
  Если cloudflared не смог запросить адрес («failed to request quick Tunnel»), вместо
  слепых перезапусков запускается диагностика сети (app/core/netcheck.py): где
  обрывается связь с Cloudflare. Нет связи — останавливаемся сразу с подсказкой.
  С включённым прокси диагностика не запускается: прямая проверка сети тут ничего не скажет.
* named (свой домен): preflight -> server -> (сервер ответил) -> tunnel -> (/ready = 200).
  Адрес постоянный. Два источника настройки:
    - мастер «Свой домен» (domain.json): `cloudflared tunnel run`, ключ туннеля — в TUNNEL_TOKEN;
    - ручная настройка по инструкции: config.yml + `cloudflared tunnel run`.
  Мастер в приоритете.

Прокси (вкладка «Прокси», proxy.json): перед каждым запуском туннеля поднимаются локальные
мосты, cloudflared получает --edge 127.0.0.1:… (и --quick-service для временного адреса),
протокол принудительно http2 — через SOCKS5/HTTP CONNECT идёт только TCP.

Остановка всегда: tunnel -> server (сначала закрываем вход извне).

Токен и адрес передаются бэкенду переменными окружения (MCP_SECRET_TOKEN,
MCP_PUBLIC_URL…), а не аргументами: аргументы видны в Диспетчере задач.
"""
from __future__ import annotations

import fnmatch
import os
import re
import socket
import threading
import time
from enum import Enum
from pathlib import Path
from urllib.parse import urlsplit

import psutil
from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from app.config import TUNNEL_MODES, TUNNEL_NAMED, Settings, normalize_public_url
from app.core import domain_state, token_store
from app.core import proxy as px
from app.core.edge_relay import ProxyBridge
from app.core.health import HealthMonitor
from app.core.netcheck import Diagnosis, diagnose_quick_tunnel
from app.core.process import ManagedProcess, ProcState
from app.paths import (
    backend_command,
    default_backend_workdir,
    is_frozen,
    project_root,
    resolve_cloudflared,
    user_data_dir,
)

SERVER = "server"
TUNNEL = "tunnel"
APP = "app"  # источник служебных сообщений в логе

SERVER_READY_TIMEOUT_MS = 20_000
QUICK_URL_TIMEOUT_MS = 60_000  # столько ждём, пока trycloudflare.com выдаст адрес
MAX_RESTARTS = 5
STABLE_UPTIME_S = 60  # проработал здоровым дольше — счётчик перезапусков сбрасывается
VALID_PROTOCOLS = {"http2", "quic", "auto"}
DOMAIN_GUIDE_HINT = "Настроить: «Подключение» → «Свой домен» (мастер по токену API Cloudflare)."

# Адрес, который cloudflared печатает в рамке для quick tunnel. api.trycloudflare.com —
# это служебный адрес из сообщений об ошибках, а не наш.
QUICK_URL_RE = re.compile(r"https://(?!api\.)[a-z0-9-]+\.trycloudflare\.com", re.IGNORECASE)
# Так cloudflared сообщает, что не получил временный адрес (cmd/cloudflared/tunnel/quick_tunnel.go).
QUICK_PROVISION_ERRORS = (
    "failed to request quick tunnel",
    "quick tunnel provisioning failed",
    "failed to unmarshal quick tunnel",
    "failed to read quick-tunnel response",
)
QUICK_CONFIG_FILE = "quick-tunnel.yml"
# Непустой конфиг: на пустой cloudflared пишет «ERR Configuration file … was empty».
QUICK_CONFIG_TEXT = (
    "# MCP app: конфиг для временного адреса (quick tunnel).\n"
    "# Нужен, чтобы cloudflared НЕ читал ~/.cloudflared/config.yml вашего именованного туннеля.\n"
    "no-autoupdate: true\n"
)
_HOSTNAME_RE = re.compile(r"^\s*-?\s*hostname:\s*['\"]?([^'\"\s#]+)", re.MULTILINE)


class Overall(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"     # сервер отвечает И туннель подключён к Cloudflare
    DEGRADED = "degraded"   # что-то упало и перезапускается
    STOPPING = "stopping"
    ERROR = "error"         # не стартовали (preflight) или исчерпаны перезапуски


class ServiceManager(QObject):
    service_state_changed = pyqtSignal(str, object)  # (SERVER|TUNNEL, ProcState)
    overall_state_changed = pyqtSignal(object)       # Overall
    log_line = pyqtSignal(str, str)                  # (SERVER|TUNNEL|APP, строка)
    public_url_changed = pyqtSignal(str)             # текущий публичный адрес ('' = ещё нет)
    token_changed = pyqtSignal()
    settings_changed = pyqtSignal()                  # режим туннеля / параметры доступа / прокси
    # Результат диагностики из фонового потока (доставляется в поток GUI очередью Qt).
    _diagnosis_ready = pyqtSignal(int, object)       # (номер запуска, Diagnosis)

    def __init__(self, settings: Settings, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.server = ManagedProcess(SERVER, self)
        self.tunnel = ManagedProcess(TUNNEL, self)
        self._procs = {SERVER: self.server, TUNNEL: self.tunnel}

        for proc in self._procs.values():
            proc.log_line.connect(self._forward_log)
            proc.state_changed.connect(self._on_proc_state)
            proc.exited.connect(self._on_exited)

        self.health = HealthMonitor(
            settings.local_host(),
            settings.server_port,
            settings.metrics_port,
            health_path=settings.server_health_path,
            parent=self,
        )
        self.health.server_health.connect(self._on_server_health)
        self.health.tunnel_health.connect(self.tunnel.mark_health)
        # Строка access-лога uvicorn от нашей же проверки: ... "GET /health HTTP/1.1" 200 ...
        self._health_log_marker = f'"GET {self.health.health_path} '
        self._quic_hint_shown = False

        # Мосты к Cloudflare через прокси. Лог из фоновых потоков мостов: emit сигнала
        # потокобезопасен, Qt доставит строку в поток GUI очередью.
        self._bridge = ProxyBridge(px.load(), log=self._log)
        self._proxy_hint_shown = False

        self._server_wait = QTimer(self)
        self._server_wait.setSingleShot(True)
        self._server_wait.timeout.connect(self._on_server_ready_timeout)

        self._quick_wait = QTimer(self)
        self._quick_wait.setSingleShot(True)
        self._quick_wait.timeout.connect(self._on_quick_url_timeout)

        self._restart_timers: dict[str, QTimer] = {}
        for name in self._procs:
            timer = QTimer(self)
            timer.setSingleShot(True)
            timer.timeout.connect(lambda n=name: self._restart(n))
            self._restart_timers[name] = timer

        self._restart_attempts = {name: 0 for name in self._procs}
        self._healthy_at: dict[str, float | None] = {name: None for name in self._procs}
        self._want_running = False
        self._error = False
        self._overall = Overall.STOPPED

        self._quick_url = ""               # адрес текущего quick tunnel ('' — ещё не выдан)
        self._server_url = ""              # с каким адресом запущен текущий сервер
        self._server_restart_pending = False  # сервер останавливается, чтобы стартовать с новым адресом
        self._restart_all_pending = False     # после остановки всё запустить снова (новые настройки)

        # Диагностика сети при сбое выдачи временного адреса — один раз за запуск.
        self._run_id = 0                   # номер запуска: старые результаты игнорируются
        self._provision_failed = False     # cloudflared написал «failed to request quick Tunnel»
        self._diagnosing = False
        self._diagnosis: Diagnosis | None = None
        self._diagnosis_ready.connect(self._on_diagnosis)

        self._token = self._load_or_create_token()

    # ================================================================== состояние
    @property
    def overall(self) -> Overall:
        return self._overall

    @property
    def is_active(self) -> bool:
        """True, пока пользователь хочет, чтобы всё работало (для кнопки Старт/Стоп)."""
        return self._want_running

    @property
    def is_quick(self) -> bool:
        return self.settings.is_quick_tunnel

    @property
    def is_diagnosing(self) -> bool:
        return self._diagnosing

    @property
    def public_url(self) -> str:
        """Адрес для клиентов. В режиме quick — '' до того, как Cloudflare его выдаст."""
        return self._quick_url if self.is_quick else self.settings.public_url

    @property
    def token(self) -> str:
        return self._token

    def url_with_token(self) -> str:
        url = self.public_url
        return f"{url}?token={self._token}" if url and self._token else url

    def cloudflared_path(self) -> str | None:
        return resolve_cloudflared(self.settings.cloudflared_path)

    # ------------------------------------------------------------------ свой домен
    def wizard_domain(self) -> domain_state.DomainState:
        """Домен из мастера (пустой DomainState, если мастер не запускали)."""
        return domain_state.load()

    def uses_wizard_domain(self) -> bool:
        return self.wizard_domain().is_configured

    def has_domain(self) -> bool:
        """Свой домен настроен — мастером или вручную (config.yml). Тогда режим просто включается."""
        return self.uses_wizard_domain() or self.settings.has_named_tunnel_config()

    # ------------------------------------------------------------------ прокси
    @property
    def proxy_settings(self) -> px.ProxySettings:
        return self._bridge.settings

    @property
    def proxy_enabled(self) -> bool:
        return self._bridge.settings.enabled

    def _proxy_edge_planned(self) -> bool:
        try:
            return bool(self._bridge.settings.edge_targets())
        except ValueError:
            return False

    @property
    def tunnel_protocol(self) -> str:
        """Протокол, с которым реально запускается cloudflared ('' — решает сам cloudflared)."""
        if self._bridge.edge_active or self._proxy_edge_planned():
            return "http2"  # через SOCKS5/HTTP CONNECT идёт только TCP
        return self.settings.tunnel_protocol.strip().lower()

    # ================================================================== изменение настроек
    def set_token(self, token: str) -> str | None:
        """Сохранить свой токен. Вернёт текст ошибки или None."""
        token = token.strip()
        if not token:
            return "Токен не может быть пустым. Нажмите «Сгенерировать», чтобы получить случайный."
        problem = token_store.problem(token)
        if problem:
            return problem
        if token == self._token:
            return None
        try:
            token_store.save(token)
        except OSError as exc:
            return f"Не удалось сохранить токен: {exc}"
        self._token = token
        self._log(f"✔ Токен изменён ({token_store.mask(token)}). Обновите его в подключённых клиентах.")
        self.token_changed.emit()
        self._restart_if_running("новый токен")
        return None

    def generate_token(self) -> str | None:
        return self.set_token(token_store.generate())

    def set_public_url(self, value: str) -> str | None:
        """Сменить свой домен (режим named). Пустая строка — убрать. Вернёт текст ошибки или None."""
        if not value.strip():
            url = ""
        else:
            url = normalize_public_url(value, self.settings.mcp_path)
            if not url:
                return "Не похоже на адрес. Пример: mcp.example.com или https://mcp.example.com/mcp"
            host = urlsplit(url).hostname or ""
            if host.endswith(".trycloudflare.com"):
                return "Адреса *.trycloudflare.com временные — выберите режим «Временный адрес»."
            wizard = self.wizard_domain()
            if wizard.is_configured and host != wizard.hostname:
                return (f"Туннель настроен мастером на {wizard.hostname}. Чтобы сменить домен, "
                        "нажмите «Настроить свой домен…» — мастер перенастроит туннель и DNS.")
        if url == self.settings.public_url:
            return None
        self.settings.public_url = url
        if not self._save_settings():
            return "Не удалось сохранить настройки (см. журнал)."
        self._log(f"✔ Публичный адрес: {url}" if url else "Адрес своего домена убран")
        self._warn_if_not_in_config()
        if not self.is_quick:
            self.public_url_changed.emit(self.public_url)
            if url:
                self._restart_if_running("новый адрес")
            elif self._want_running:
                self.stop_all()  # без адреса именованный туннель работать не должен
        return None

    def apply_domain(self, state: domain_state.DomainState) -> str | None:
        """Мастер настроил домен: включить режим «Свой домен» с его адресом. Ошибка или None."""
        url = normalize_public_url(state.hostname, self.settings.mcp_path)
        if not url or not state.is_configured:
            return "Мастер не вернул адрес или ключ туннеля."
        self.settings.public_url = url
        self.settings.tunnel_mode = TUNNEL_NAMED
        if not self._save_settings():
            return "Не удалось сохранить настройки (см. журнал)."
        self._quick_url = ""
        self._log(f"✔ Свой домен настроен: {url}")
        self.settings_changed.emit()
        self.public_url_changed.emit(self.public_url)
        self._restart_if_running("свой домен настроен")  # ключ туннеля мог смениться
        return None

    def apply_proxy_settings(self, settings: px.ProxySettings) -> None:
        """Вкладка «Прокси» сохранила настройки: применить при следующем запуске туннеля."""
        self._bridge.settings = settings
        self._proxy_hint_shown = False
        self._log("Прокси для хостов Cloudflare " + ("включён" if settings.enabled else "выключен"))
        self.settings_changed.emit()
        self._restart_if_running("новые настройки прокси")

    def set_tunnel_mode(self, mode: str) -> None:
        if mode not in TUNNEL_MODES or mode == self.settings.tunnel_mode:
            return
        self.settings.tunnel_mode = mode
        self._save_settings()
        self._quick_url = ""
        label = "временный адрес trycloudflare.com" if self.is_quick else "свой домен"
        self._log(f"Режим туннеля: {label}")
        self.settings_changed.emit()
        self.public_url_changed.emit(self.public_url)
        self._restart_if_running("другой режим туннеля")

    def set_allow_query_token(self, enabled: bool) -> None:
        if enabled == self.settings.allow_query_token:
            return
        self.settings.allow_query_token = enabled
        self._save_settings()
        self.settings_changed.emit()
        self._restart_if_running("изменены параметры доступа")

    # ================================================================== старт / стоп
    def toggle(self) -> None:
        if self._want_running:
            self.stop_all()
        else:
            self.start_all()

    def start_all(self) -> None:
        if self._want_running:
            return
        self._error = False
        problems = self.preflight()
        if problems:
            for msg in problems:
                self._log(f"✖ {msg}")
            self._error = True
            self._recompute()
            return
        self._want_running = True
        self._run_id += 1
        self._diagnosis = None
        self._diagnosing = False
        self._restart_attempts = {name: 0 for name in self._procs}
        self._healthy_at = {name: None for name in self._procs}
        self._quic_hint_shown = False
        self._proxy_hint_shown = False
        self._set_quick_url("")
        self.health.start()
        if self.is_quick:
            self._log("Запуск: сначала туннель — жду временный адрес от Cloudflare…")
            self._start_tunnel()
        else:
            self._log("Запуск сервисов…")
            self._start_server()
        self._recompute()

    def stop_all(self) -> None:
        """Неблокирующая остановка (кнопка «Остановить»)."""
        self._halt()
        self._log("Остановка сервисов…")
        self.tunnel.stop()
        self.server.stop()
        self._recompute()

    def shutdown(self) -> None:
        """Блокирующая остановка — только при выходе из приложения (до 2×3 с)."""
        self._restart_all_pending = False
        self._halt()
        self.tunnel.stop_blocking()
        self.server.stop_blocking()

    def preflight(self) -> list[str]:
        """Проверки до старта. Возвращает список блокирующих проблем (пусто = можно)."""
        s = self.settings
        problems: list[str] = []

        if not is_frozen() and not (project_root() / "backend" / "server.py").is_file():
            problems.append("Не найден backend/server.py.")

        if self.cloudflared_path() is None:
            problems.append(
                "cloudflared.exe не найден. Установите его (winget install --id Cloudflare.cloudflared) "
                "или укажите путь в настройках."
            )
        if not self.is_quick:
            if not self.has_domain():
                problems.append(
                    f"Свой домен ещё не настроен. {DOMAIN_GUIDE_HINT} "
                    "Без домена выберите режим «Временный адрес»."
                )
            elif not s.has_public_url:
                problems.append(
                    "Не указан адрес своего домена. Введите его в «Подключение» → «Публичный адрес» "
                    "(тот же hostname, что в config.yml)."
                )
            else:
                self._warn_if_not_in_config()
        protocol = s.tunnel_protocol.strip().lower()
        if protocol and protocol not in VALID_PROTOCOLS:
            problems.append(f"tunnel_protocol='{s.tunnel_protocol}' — допустимо: http2, quic, auto или пусто.")

        self._bridge.settings = px.load()
        if self._bridge.settings.enabled:
            for error in self._bridge.settings.validate():
                problems.append(f"Прокси: {error}. Исправьте во вкладке «Прокси» или выключите прокси.")

        checks = ((s.local_host(), s.server_port, "MCP-сервера"), ("127.0.0.1", s.metrics_port, "метрик cloudflared"))
        for host, port, what in checks:
            owner = _port_owner(host, port)
            if owner:
                problems.append(f"Порт {port} ({what}) уже занят: {owner}. Закройте старое окно терминала.")

        strays = _foreign_cloudflared()
        if strays:
            # Не блокируем: два коннектора одного туннеля допустимы, но это путает отладку.
            self._log(f"⚠ Уже запущен cloudflared вне приложения (PID {', '.join(map(str, strays))}).")

        return problems

    # ================================================================== запуск процессов
    def _server_env(self) -> dict[str, str]:
        s = self.settings
        return {
            "MCP_SECRET_TOKEN": self._token,
            "MCP_PUBLIC_URL": self.public_url,
            "MCP_HOST": s.server_host,
            "MCP_PORT": str(s.server_port),
            "MCP_HEALTH_PATH": s.server_health_path,
            "MCP_ALLOW_QUERY_TOKEN": "1" if s.allow_query_token else "0",
            # Quick Tunnels не поддерживают SSE: отвечаем обычным JSON.
            "MCP_JSON_RESPONSE": "1" if self.is_quick else "0",
        }

    def _start_server(self) -> None:
        program, args = backend_command()
        workdir = self.settings.backend_workdir or str(default_backend_workdir())
        Path(workdir).mkdir(parents=True, exist_ok=True)
        env = self._server_env()
        self._server_url = env["MCP_PUBLIC_URL"]
        self.server.start(program, args, workdir=workdir, env=env)
        self._server_wait.start(SERVER_READY_TIMEOUT_MS)

    def tunnel_args(self) -> list[str]:
        """Аргументы cloudflared. Все флаги — уровня `tunnel`, поэтому стоят ДО `run`.

        Мастер: свой config.yml не нужен (ingress хранится в Cloudflare), поэтому, как и для
        временного адреса, передаём нейтральный конфиг — иначе cloudflared подхватит
        ~/.cloudflared/config.yml от ручной настройки.
        """
        s = self.settings
        wizard = not self.is_quick and self.uses_wizard_domain()
        if self.is_quick or wizard:
            config = _quick_tunnel_config()
        else:
            config = Path(s.cloudflared_config).expanduser()
        args = [
            "tunnel",
            "--no-autoupdate",                          # обновления — наша забота, не процесса
            "--config", str(config),
            "--metrics", f"127.0.0.1:{s.metrics_port}",  # для /ready
        ]
        protocol = self.tunnel_protocol
        if protocol:
            # http2 = TCP вместо QUIC/UDP 7844, который режет провайдер (и единственный вариант через прокси).
            args += ["--protocol", protocol]
        args += self._bridge.cloudflared_args(self.is_quick)  # --edge … / --quick-service …
        if self.is_quick:
            args += ["--url", f"http://{s.local_host()}:{s.server_port}"]
        else:
            args.append("run")  # мастер: туннель по TUNNEL_TOKEN; вручную: имя/UUID из config.yml
        return args

    def _tunnel_env(self) -> dict[str, str]:
        """Ключ туннеля из мастера — переменной окружения (`--token` читает TUNNEL_TOKEN)."""
        if self.is_quick:
            return {}
        wizard = self.wizard_domain()
        return {"TUNNEL_TOKEN": wizard.tunnel_token} if wizard.is_configured else {}

    def _start_tunnel(self) -> None:
        if self.tunnel.is_alive():
            return  # мосты нельзя пересоздавать под живым процессом
        exe = self.cloudflared_path()
        if exe is None:
            self._log("✖ cloudflared.exe не найден")
            self._fail()
            return
        self._bridge.settings = px.load()
        try:
            self._bridge.start()
        except (ValueError, OSError) as exc:
            self._log(f"✖ Прокси: {exc}. Исправьте во вкладке «Прокси» или выключите прокси.")
            self._fail()
            return
        configured = self.settings.tunnel_protocol.strip().lower()
        if self._bridge.edge_active and configured not in ("", "http2") and not self._proxy_hint_shown:
            self._proxy_hint_shown = True
            self._log(f"⚠ Через прокси туннель работает только по HTTP/2 — tunnel_protocol={configured} "
                      "из settings.json сейчас не применяется.")
        self._provision_failed = False
        self.tunnel.start(exe, self.tunnel_args(), env=self._tunnel_env())
        self.health.check_tunnel = True
        if self.is_quick and not self._quick_url:
            self._quick_wait.start(QUICK_URL_TIMEOUT_MS)

    def _restart(self, name: str) -> None:
        if not self._want_running:
            return
        self._log(f"↻ Перезапуск {name} (попытка {self._restart_attempts[name]}/{MAX_RESTARTS})")
        if name == SERVER:
            self._start_server()
        else:
            self._start_tunnel()
        self._recompute()

    def _restart_if_running(self, reason: str) -> None:
        """Новые настройки применяются только при старте: остановить и запустить снова."""
        if not self._want_running:
            return
        self._log(f"↻ Перезапуск сервисов: {reason}")
        self._restart_all_pending = True
        self.stop_all()

    # ================================================================== диагностика сети
    def _begin_diagnosis(self) -> None:
        """cloudflared не получил временный адрес: выяснить, где обрывается связь.

        Пока идёт проверка (до ~40 с, в фоновом потоке), перезапуски на паузе.
        Нет связи — остановка с объяснением; связь есть — обычные перезапуски.
        """
        self._diagnosing = True
        self._quick_wait.stop()
        self._log("⚠ Cloudflare не выдал временный адрес (нет ответа от api.trycloudflare.com). "
                  "Проверяю связь с Cloudflare…")
        run_id = self._run_id

        def work() -> None:
            try:
                result = diagnose_quick_tunnel()
            except Exception as exc:  # noqa: BLE001 — диагностика не должна ронять приложение
                result = Diagnosis(True, f"Проверка связи не удалась: {exc}")
            self._diagnosis_ready.emit(run_id, result)

        threading.Thread(target=work, name="netcheck", daemon=True).start()
        self._recompute()

    def _on_diagnosis(self, run_id: int, diagnosis: Diagnosis) -> None:
        if run_id != self._run_id or not self._want_running or not self._diagnosing:
            return  # пользователь уже остановил или перезапустил
        self._diagnosing = False
        self._diagnosis = diagnosis
        self._log(("⚠ " if diagnosis.reachable else "✖ ") + diagnosis.summary)
        for tip in diagnosis.advice:
            self._log(f"   • {tip}")
        if not diagnosis.reachable:
            self._log("✖ Временный адрес с этой сетью не получить — останавливаю. "
                      "Исправьте связь или включите прокси во вкладке «Прокси» и нажмите «Запустить» снова.")
            self._fail()
            return
        self._schedule_restart(TUNNEL, 1)

    # ================================================================== слоты
    def _forward_log(self, name: str, line: str) -> None:
        if name == SERVER and self._health_log_marker in line:
            return  # свои же проверки раз в 2 с не засоряют лог
        self.log_line.emit(name, line)
        if name != TUNNEL:
            return
        low = line.lower()
        if self.is_quick and self._want_running:
            match = QUICK_URL_RE.search(line)
            if match:
                self._on_quick_url(match.group(0).lower())
            elif any(marker in low for marker in QUICK_PROVISION_ERRORS):
                self._provision_failed = True
        # Подсказка про QUIC нужна, только если мы сами его используем. При http2
        # cloudflared всё равно проверяет UDP и пишет «QUIC connection failed» — это норма.
        protocol = self.tunnel_protocol
        if (protocol != "http2" and not self._quic_hint_shown
                and "quic" in low and "failed" in low):
            self._quic_hint_shown = True
            self._log("⚠ QUIC (UDP 7844) не проходит. Укажите \"tunnel_protocol\": \"http2\" в settings.json "
                      "и уберите protocol: quic из config.yml.")

    def _on_quick_url(self, origin: str) -> None:
        url = origin + self.settings.mcp_path
        if url == self._quick_url:
            return
        self._quick_wait.stop()
        self._set_quick_url(url)
        self._log(f"✔ Временный адрес: {url}")
        if not self.server.is_alive():
            if not self._restart_timers[SERVER].isActive():
                self._start_server()
        elif self._server_url != url:
            # cloudflared перезапустился и получил другой адрес — сервер должен знать новый.
            self._log("↻ Адрес изменился — перезапускаю сервер")
            self._server_restart_pending = True
            self._server_wait.stop()
            self.server.stop()
        self._recompute()

    def _on_quick_url_timeout(self) -> None:
        if self._want_running and self.is_quick and not self._quick_url and not self._diagnosing:
            self._log(f"✖ Cloudflare не выдал временный адрес за {QUICK_URL_TIMEOUT_MS // 1000} с. "
                      "trycloudflare.com иногда ограничивает выдачу — попробуйте позже "
                      f"или подключите свой домен. {DOMAIN_GUIDE_HINT}")
            self._fail()

    def _on_server_health(self, ok: bool) -> None:
        self.server.mark_health(ok)
        if ok and self._want_running and self.server.is_alive():
            self._server_wait.stop()
            # named: туннель стартует только когда есть куда проксировать — иначе клиенты
            # получат 502. quick: туннель уже работает, сервер запускался вторым.
            if (not self.is_quick and not self.tunnel.is_alive()
                    and not self._restart_timers[TUNNEL].isActive()):
                self._start_tunnel()

    def _on_server_ready_timeout(self) -> None:
        if self._want_running and self.server.state != ProcState.RUNNING:
            self._log(f"✖ Сервер не ответил на порту {self.settings.server_port} за {SERVER_READY_TIMEOUT_MS // 1000} с")
            self._fail()

    def _on_exited(self, name: str, exit_code: int, expected: bool) -> None:
        if name == TUNNEL and self.is_quick and self._quick_url:
            self._set_quick_url("")  # старый адрес умер вместе с процессом
        if name == SERVER and expected and self._server_restart_pending:
            self._server_restart_pending = False
            if self._want_running:
                self._start_server()
                self._recompute()
                return
        if expected or not self._want_running:
            self._recompute()
            return
        if name == SERVER:
            self._server_wait.stop()
        if (name == TUNNEL and self.is_quick and self._provision_failed
                and self._diagnosis is None and not self._diagnosing):
            if self._bridge.active:
                # Связь идёт через прокси: прямая проверка сети ничего не покажет.
                if not self._proxy_hint_shown:
                    self._proxy_hint_shown = True
                    self._log("⚠ Через прокси временный адрес не выдан. Проверьте прокси: "
                              "«Прокси» → «Проверить».")
            else:
                # Первый сбой выдачи адреса за запуск: сначала проверить сеть, потом решать.
                self._begin_diagnosis()
                return
        self._schedule_restart(name, exit_code)

    def _schedule_restart(self, name: str, exit_code: int) -> None:
        if not self.settings.auto_restart:
            self._log(f"✖ {name} упал (код {exit_code}); автоперезапуск выключен")
            self._fail()
            return

        healthy_at = self._healthy_at[name]
        if healthy_at is not None and time.monotonic() - healthy_at > STABLE_UPTIME_S:
            self._restart_attempts[name] = 0  # долго работал — это не crash-loop
        self._healthy_at[name] = None
        self._restart_attempts[name] += 1
        attempt = self._restart_attempts[name]
        if attempt > MAX_RESTARTS:
            self._log(f"✖ {name} падает слишком часто — останавливаю всё")
            if name == TUNNEL and self.is_quick and not self._quick_url:
                self._log(f"   • Временный адрес так и не выдан. Попробуйте позже или подключите свой домен. "
                          f"{DOMAIN_GUIDE_HINT}")
            self._fail()
            return
        delay_s = min(2 ** attempt, 30)  # 2, 4, 8, 16, 30
        self._log(f"⚠ {name} упал (код {exit_code}), перезапуск через {delay_s} с")
        self._restart_timers[name].start(delay_s * 1000)
        self._recompute()

    def _on_proc_state(self, name: str, state: ProcState) -> None:
        if state == ProcState.RUNNING:
            if self._healthy_at[name] is None:
                self._healthy_at[name] = time.monotonic()
            self._log("✔ Сервер отвечает" if name == SERVER else "✔ Туннель подключён к Cloudflare")
        self.service_state_changed.emit(name, state)
        self._recompute()

    # ================================================================== helpers
    def _load_or_create_token(self) -> str:
        token = token_store.load()
        if token:
            return token
        # Первый запуск: если токен уже задан переменной окружения, берём его —
        # иначе уже подключённые Notion/ChatGPT потеряли бы доступ.
        env_token = os.environ.get("MCP_SECRET_TOKEN", "").strip()
        if env_token and not any(ch.isspace() for ch in env_token):
            token, origin = env_token, "взят из переменной MCP_SECRET_TOKEN"
        else:
            token, origin = token_store.generate(), "сгенерирован новый — скопируйте его в клиенты"
        try:
            token_store.save(token)
            note = f"Токен доступа {origin} ({token_store.mask(token)})"
        except OSError as exc:
            note = f"⚠ Токен не сохранён ({exc}) — после перезапуска будет новый"
        QTimer.singleShot(0, lambda: self._log(note))  # окно ещё не подписалось на лог
        return token

    def _set_quick_url(self, url: str) -> None:
        if url != self._quick_url:
            self._quick_url = url
            if self.is_quick:
                self.public_url_changed.emit(url)

    def _warn_if_not_in_config(self) -> None:
        """Адрес из приложения не меняет DNS: hostname должен быть в ingress config.yml."""
        if self.uses_wizard_domain():
            return  # ingress и DNS настроил мастер, config.yml не используется
        host = urlsplit(self.settings.public_url).hostname or ""
        hosts = _config_hostnames(Path(self.settings.cloudflared_config).expanduser())
        if host and hosts and not any(fnmatch.fnmatch(host, pattern) for pattern in hosts):
            self._log(
                f"⚠ {host} нет в ingress config.yml ({', '.join(hosts)}). Добавьте hostname в config.yml "
                f"и выполните: cloudflared tunnel route dns <имя-туннеля> {host}"
            )

    def _save_settings(self) -> bool:
        try:
            self.settings.save()
            return True
        except OSError as exc:
            self._log(f"✖ Не удалось сохранить настройки: {exc}")
            return False

    def _halt(self) -> None:
        self._want_running = False
        self._server_restart_pending = False
        self._diagnosing = False
        self._server_wait.stop()
        self._quick_wait.stop()
        for timer in self._restart_timers.values():
            timer.stop()
        self.health.stop()
        self._bridge.stop()

    def _fail(self) -> None:
        self._error = True
        self._restart_all_pending = False
        self.stop_all()

    def _recompute(self) -> None:
        states = {self.server.state, self.tunnel.state}
        if self._want_running:
            if states == {ProcState.RUNNING}:
                overall = Overall.RUNNING
            elif (ProcState.FAILED in states or self._diagnosing
                  or any(t.isActive() for t in self._restart_timers.values())):
                overall = Overall.DEGRADED
            else:
                overall = Overall.STARTING
        elif self.server.is_alive() or self.tunnel.is_alive():
            overall = Overall.STOPPING
        else:
            overall = Overall.ERROR if self._error else Overall.STOPPED
        if overall != self._overall:
            self._overall = overall
            self.overall_state_changed.emit(overall)
        if overall == Overall.STOPPED and self._restart_all_pending:
            self._restart_all_pending = False
            QTimer.singleShot(0, self.start_all)

    def _log(self, text: str) -> None:
        self.log_line.emit(APP, text)


# ====================================================================== утилиты
def _quick_tunnel_config() -> Path:
    """Нейтральный конфиг (содержимое — QUICK_CONFIG_TEXT): временный адрес и туннель мастера.

    Без явного --config cloudflared подхватит ~/.cloudflared/config.yml со своим
    `tunnel:` и ingress — и временный адрес не получится, а туннель мастера получит чужой ingress.
    """
    path = user_data_dir() / QUICK_CONFIG_FILE
    try:
        current = path.read_text(encoding="utf-8")
    except OSError:
        current = ""
    if current != QUICK_CONFIG_TEXT:
        path.write_text(QUICK_CONFIG_TEXT, encoding="utf-8")
    return path


def _config_hostnames(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return [h.lower() for h in _HOSTNAME_RE.findall(text)]


def _port_owner(host: str, port: int) -> str | None:
    """Если порт занят — вернуть описание владельца, иначе None. Быстро (<300 мс)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        if sock.connect_ex((host, port)) != 0:
            return None
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.laddr and conn.laddr.port == port and conn.status == psutil.CONN_LISTEN and conn.pid:
                try:
                    return f"{psutil.Process(conn.pid).name()} (PID {conn.pid})"
                except psutil.Error:
                    return f"PID {conn.pid}"
    except psutil.Error:
        pass
    return "неизвестный процесс"


def _foreign_cloudflared() -> list[int]:
    """PID'ы cloudflared, запущенных НЕ нами (вручную в терминале или как служба Windows)."""
    pids = []
    for proc in psutil.process_iter(["name"]):
        if (proc.info.get("name") or "").lower() == "cloudflared.exe":
            pids.append(proc.pid)
    return pids
