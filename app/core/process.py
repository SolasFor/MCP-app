"""Обёртка над QProcess для одного дочернего сервиса (server или tunnel).

Ключевое: QProcess асинхронен и живёт в цикле событий Qt. Никаких потоков,
никаких блокирующих readline(): когда у процесса появляется вывод, Qt сам
вызывает _on_output(), и мы отдаём строки наружу сигналом log_line.
Поэтому интерфейс не зависает ни при старте, ни при потоке логов.
"""
from __future__ import annotations

import codecs
import time
from enum import Enum

from PyQt6.QtCore import QObject, QProcess, QProcessEnvironment, pyqtSignal

from app.core import winjob


class ProcState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"   # процесс жив, health-check ещё не прошёл
    RUNNING = "running"     # процесс жив И отвечает на health-check
    STOPPING = "stopping"
    FAILED = "failed"       # упал или не смог стартовать


_NOT_RUNNING = QProcess.ProcessState.NotRunning


class ManagedProcess(QObject):
    state_changed = pyqtSignal(str, object)   # (name, ProcState)
    log_line = pyqtSignal(str, str)           # (name, строка лога)
    exited = pyqtSignal(str, int, bool)       # (name, exit_code, expected=остановлен нами)

    def __init__(self, name: str, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.name = name
        self._proc: QProcess | None = None
        self._state = ProcState.STOPPED
        self._stop_requested = False
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._buffer = ""
        self.healthy_since: float | None = None

    # ------------------------------------------------------------------ props
    @property
    def state(self) -> ProcState:
        return self._state

    @property
    def pid(self) -> int | None:
        if self._proc is None:
            return None
        pid = int(self._proc.processId())
        return pid or None

    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.state() != _NOT_RUNNING

    def uptime_healthy(self) -> float:
        return time.monotonic() - self.healthy_since if self.healthy_since else 0.0

    # ------------------------------------------------------------------ control
    def start(self, program: str, args: list[str], workdir: str | None = None,
              env: dict[str, str] | None = None) -> None:
        if self.is_alive():
            return
        self._stop_requested = False
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._buffer = ""
        self.healthy_since = None

        proc = QProcess(self)
        proc.setProgram(program)
        proc.setArguments(args)
        if workdir:
            proc.setWorkingDirectory(workdir)

        environment = QProcessEnvironment.systemEnvironment()
        environment.insert("PYTHONUNBUFFERED", "1")   # логи сервера приходят сразу, а не пачками
        environment.insert("PYTHONIOENCODING", "utf-8")
        for key, value in (env or {}).items():
            environment.insert(key, value)
        proc.setProcessEnvironment(environment)

        # stdout + stderr в один канал: сохраняется порядок строк.
        # cloudflared и uvicorn пишут почти всё в stderr.
        proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        # Примечание: если у GUI нет консоли (.exe --windowed / pythonw), Qt сам ставит
        # CREATE_NO_WINDOW — чёрные окна консоли не всплывают.

        proc.readyReadStandardOutput.connect(self._on_output)
        proc.started.connect(self._on_started)
        proc.errorOccurred.connect(self._on_error)
        proc.finished.connect(self._on_finished)

        self._proc = proc
        self._set_state(ProcState.STARTING)
        self._emit(f"▶ {program} {' '.join(args)}")
        proc.start()

    def stop(self) -> None:
        """Неблокирующая остановка. Итог придёт сигналом exited/state_changed.

        На Windows у консольных процессов нет SIGTERM, а QProcess.terminate() шлёт
        WM_CLOSE, который они не получают. Поэтому убиваем дерево целиком —
        для server.py и cloudflared это безопасно (Cloudflare сам снимает коннектор).
        """
        if not self.is_alive():
            self._set_state(ProcState.STOPPED)
            return
        self._stop_requested = True
        self._set_state(ProcState.STOPPING)
        pid = self.pid
        if pid:
            winjob.kill_process_tree(pid, include_parent=False)  # внуки (команды из MCP)
        assert self._proc is not None
        self._proc.kill()

    def stop_blocking(self, timeout_ms: int = 3000) -> None:
        """Только для выхода из приложения: ждём фактического завершения."""
        proc = self._proc
        self.stop()
        if proc is not None and proc.state() != _NOT_RUNNING:
            proc.waitForFinished(timeout_ms)

    def mark_health(self, ok: bool) -> None:
        """Результат health-check от HealthMonitor: STARTING <-> RUNNING."""
        if ok and self._state == ProcState.STARTING and self.is_alive():
            self.healthy_since = time.monotonic()
            self._set_state(ProcState.RUNNING)
        elif not ok and self._state == ProcState.RUNNING:
            self.healthy_since = None
            self._set_state(ProcState.STARTING)  # процесс жив, но не отвечает

    # ------------------------------------------------------------------ slots
    def _on_started(self) -> None:
        pid = self.pid
        in_job = bool(pid) and winjob.assign_to_job(pid)
        self._emit(f"PID {pid}" + (" (Job Object)" if in_job else ""))

    def _on_output(self) -> None:
        if self._proc is None:
            return
        chunk = bytes(self._proc.readAllStandardOutput())
        self._buffer += self._decoder.decode(chunk)
        *lines, self._buffer = self._buffer.split("\n")
        for line in lines:
            line = line.rstrip("\r")
            if line:
                self.log_line.emit(self.name, line)

    def _on_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.FailedToStart:
            reason = self._proc.errorString() if self._proc else "unknown"
            self._emit(f"✖ не удалось запустить: {reason}")
            self._cleanup()
            self._set_state(ProcState.FAILED)
            self.exited.emit(self.name, -1, False)
        # Crashed обрабатывается в _on_finished (он приходит следом).

    def _on_finished(self, exit_code: int, _status: QProcess.ExitStatus) -> None:
        self._on_output()
        tail = self._decoder.decode(b"", final=True) + self._buffer
        if tail.strip():
            self.log_line.emit(self.name, tail.strip())
        self._buffer = ""

        expected = self._stop_requested
        self._emit(f"■ завершён, код {exit_code}" + ("" if expected else " (неожиданно)"))
        self._cleanup()
        self._set_state(ProcState.STOPPED if expected else ProcState.FAILED)
        self.exited.emit(self.name, exit_code, expected)

    # ------------------------------------------------------------------ helpers
    def _cleanup(self) -> None:
        if self._proc is not None:
            self._proc.deleteLater()
            self._proc = None
        self.healthy_since = None

    def _set_state(self, state: ProcState) -> None:
        if state != self._state:
            self._state = state
            self.state_changed.emit(self.name, state)

    def _emit(self, text: str) -> None:
        self.log_line.emit(self.name, text)
