"""Асинхронные health-check'и — ни одна проверка не блокирует GUI-поток.

* Сервер: TCP-подключение к 127.0.0.1:8000 (QTcpSocket). Порт принимает соединения ->
  uvicorn поднялся. Без HTTP-запроса, чтобы не засорять souron_audit.log и не зависеть
  от аутентификации.
* Туннель: cloudflared запускается с --metrics 127.0.0.1:20241, а его эндпоинт /ready
  отвечает 200, только когда есть хотя бы одно активное соединение с сетью Cloudflare.
  Это честный признак «Туннель: Активен», а не просто «процесс запущен».
"""
from __future__ import annotations

from PyQt6.QtCore import QObject, QTimer, QUrl, pyqtSignal
from PyQt6.QtNetwork import (
    QAbstractSocket,
    QNetworkAccessManager,
    QNetworkProxy,
    QNetworkReply,
    QNetworkRequest,
    QTcpSocket,
)

PROBE_TIMEOUT_MS = 1500


class HealthMonitor(QObject):
    server_health = pyqtSignal(bool)
    tunnel_health = pyqtSignal(bool)

    def __init__(self, host: str, port: int, metrics_port: int,
                 interval_ms: int = 2000, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._host = host
        self._port = port
        self._ready_url = QUrl(f"http://127.0.0.1:{metrics_port}/ready")

        self._nam = QNetworkAccessManager(self)
        self._nam.setProxy(QNetworkProxy(QNetworkProxy.ProxyType.NoProxy))  # localhost мимо системного прокси

        self._timer = QTimer(self)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self.probe_now)

        self._socket: QTcpSocket | None = None
        self._reply: QNetworkReply | None = None
        self.check_tunnel = False  # включает ServiceManager, когда туннель запущен

    def start(self) -> None:
        if not self._timer.isActive():
            self._timer.start()
            QTimer.singleShot(300, self.probe_now)  # первая проверка почти сразу

    def stop(self) -> None:
        self._timer.stop()
        self.check_tunnel = False
        if self._socket is not None:
            self._socket.abort()
        if self._reply is not None:
            self._reply.abort()

    def probe_now(self) -> None:
        self._probe_server()
        if self.check_tunnel:
            self._probe_tunnel()

    # ------------------------------------------------------------------ server
    def _probe_server(self) -> None:
        if self._socket is not None:  # предыдущая проверка ещё идёт
            return
        sock = QTcpSocket(self)
        sock.setProxy(QNetworkProxy(QNetworkProxy.ProxyType.NoProxy))
        self._socket = sock
        done = False

        def finish(ok: bool) -> None:
            nonlocal done
            if done:
                return
            done = True
            self._socket = None
            sock.abort()
            sock.deleteLater()
            self.server_health.emit(ok)

        sock.connected.connect(lambda: finish(True))
        sock.errorOccurred.connect(lambda _err: finish(False))
        QTimer.singleShot(PROBE_TIMEOUT_MS, lambda: finish(
            sock.state() == QAbstractSocket.SocketState.ConnectedState))
        sock.connectToHost(self._host, self._port)

    # ------------------------------------------------------------------ tunnel
    def _probe_tunnel(self) -> None:
        if self._reply is not None:
            return
        request = QNetworkRequest(self._ready_url)
        request.setTransferTimeout(PROBE_TIMEOUT_MS)
        reply = self._nam.get(request)
        self._reply = reply

        def on_finished() -> None:
            status = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
            self._reply = None
            reply.deleteLater()
            self.tunnel_health.emit(status == 200)

        reply.finished.connect(on_finished)
