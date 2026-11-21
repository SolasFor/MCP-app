"""Оркестратор: единственная точка, с которой разговаривает GUI.

    GUI ──start_all()/stop_all()──▶ ServiceManager ──▶ ManagedProcess("server")
    GUI ◀─────── сигналы ──────── ServiceManager ──▶ ManagedProcess("tunnel")
                                         │
                                         └──▶ HealthMonitor (TCP :8000, /ready)

Порядок старта: preflight -> server -> (порт 8000 ответил) -> tunnel -> (/ready = 200).
Порядок остановки: tunnel -> server (сначала закрываем вход извне).
"""
from __future__ import annotations

import socket
import time
from enum import Enum
from pathlib import Path

import psutil
from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from app.config import Settings
from app.core.health import HealthMonitor
from app.core.process import ManagedProcess, ProcState
from app.paths import backend_command, default_backend_workdir, is_frozen, project_root, resolve_cloudflared

SERVER = "server"
TUNNEL = "tunnel"
APP = "app"  # источник служебных сообщений в логе

SERVER_READY_TIMEOUT_MS = 20_000
MAX_RESTARTS = 5
STABLE_UPTIME_S = 60  # проработал здоровым дольше — счётчик перезапусков сбрасывается


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

    def __init__(self, settings: Settings, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.server = ManagedProcess(SERVER, self)
        self.tunnel = ManagedProcess(TUNNEL, self)
        self._procs = {SERVER: self.server, TUNNEL: self.tunnel}

        for proc in self._procs.values():
            proc.log_line.connect(self.log_line)
            proc.state_changed.connect(self._on_proc_state)
            proc.exited.connect(self._on_exited)

        self.health = HealthMonitor(settings.server_host, settings.server_port, settings.metrics_port, parent=self)
        self.health.server_health.connect(self._on_server_health)
        self.health.tunnel_health.connect(self.tunnel.mark_health)

        self._server_wait = QTimer(self)
        self._server_wait.setSingleShot(True)
        self._server_wait.timeout.connect(self._on_server_ready_timeout)

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

    # ================================================================== API для GUI
    @property
    def overall(self) -> Overall:
        return self._overall

    @property
    def is_active(self) -> bool:
        """True, пока пользователь хочет, чтобы всё работало (для кнопки Старт/Стоп)."""
        return self._want_running

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
        self._restart_attempts = {name: 0 for name in self._procs}
        self._healthy_at = {name: None for name in self._procs}
        self._log("Запуск сервисов…")
        self.health.start()
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
        self._halt()
        self.tunnel.stop_blocking()
        self.server.stop_blocking()

    def preflight(self) -> list[str]:
        """Проверки до старта. Возвращает список блокирующих проблем (пусто = можно)."""
        s = self.settings
        problems: list[str] = []

        if not is_frozen() and not (project_root() / "backend" / "server.py").is_file():
            problems.append("Не найден backend/server.py — скопируйте туда ваш server.py.")

        if resolve_cloudflared(s.cloudflared_path) is None:
            problems.append("cloudflared.exe не найден (настройки, bin/, Program Files, PATH).")
        if not Path(s.cloudflared_config).expanduser().is_file():
            problems.append(f"Не найден конфиг туннеля: {s.cloudflared_config}")

        checks = ((s.server_host, s.server_port, "MCP-сервера"), ("127.0.0.1", s.metrics_port, "метрик cloudflared"))
        for host, port, what in checks:
            owner = _port_owner(host, port)
            if owner:
                problems.append(f"Порт {port} ({what}) уже занят: {owner}. Закройте старое окно терминала.")

        strays = _foreign_cloudflared()
        if strays:
            # Не блокируем: два коннектора одного туннеля допустимы, но это путает отладку.
            self._log(f"⚠ Уже запущен cloudflared вне приложения (PID {', '.join(map(str, strays))}).")

        return problems

    # ================================================================== запуск
    def _start_server(self) -> None:
        program, args = backend_command()
        workdir = self.settings.backend_workdir or str(default_backend_workdir())
        Path(workdir).mkdir(parents=True, exist_ok=True)
        self.server.start(program, args, workdir=workdir)
        self._server_wait.start(SERVER_READY_TIMEOUT_MS)

    def _start_tunnel(self) -> None:
        s = self.settings
        exe = resolve_cloudflared(s.cloudflared_path)
        if exe is None:
            self._log("✖ cloudflared.exe не найден")
            self._fail()
            return
        args = [
            "tunnel",
            "--no-autoupdate",                          # обновления — наша забота, не процесса
            "--config", str(Path(s.cloudflared_config).expanduser()),
            "--metrics", f"127.0.0.1:{s.metrics_port}",  # для /ready
            "run",                                      # имя/UUID туннеля берётся из config.yml
        ]
        self.tunnel.start(exe, args)
        self.health.check_tunnel = True

    def _restart(self, name: str) -> None:
        if not self._want_running:
            return
        self._log(f"↻ Перезапуск {name} (попытка {self._restart_attempts[name]}/{MAX_RESTARTS})")
        if name == SERVER:
            self._start_server()
        else:
            self._start_tunnel()
        self._recompute()

    # ================================================================== слоты
    def _on_server_health(self, ok: bool) -> None:
        self.server.mark_health(ok)
        if ok and self._want_running and self.server.is_alive():
            self._server_wait.stop()
            # Туннель стартует только когда есть куда проксировать — иначе клиенты получат 502.
            if not self.tunnel.is_alive() and not self._restart_timers[TUNNEL].isActive():
                self._start_tunnel()

    def _on_server_ready_timeout(self) -> None:
        if self._want_running and self.server.state != ProcState.RUNNING:
            self._log(f"✖ Сервер не открыл порт {self.settings.server_port} за {SERVER_READY_TIMEOUT_MS // 1000} с")
            self._fail()

    def _on_exited(self, name: str, exit_code: int, expected: bool) -> None:
        if expected or not self._want_running:
            self._recompute()
            return
        if name == SERVER:
            self._server_wait.stop()
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
    def _halt(self) -> None:
        self._want_running = False
        self._server_wait.stop()
        for timer in self._restart_timers.values():
            timer.stop()
        self.health.stop()

    def _fail(self) -> None:
        self._error = True
        self.stop_all()

    def _recompute(self) -> None:
        states = {self.server.state, self.tunnel.state}
        if self._want_running:
            if states == {ProcState.RUNNING}:
                overall = Overall.RUNNING
            elif ProcState.FAILED in states or any(t.isActive() for t in self._restart_timers.values()):
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

    def _log(self, text: str) -> None:
        self.log_line.emit(APP, text)


# ====================================================================== утилиты
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
