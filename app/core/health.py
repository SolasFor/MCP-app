"""Асинхронные health-check'и — ни одна проверка не блокирует GUI-поток.

* Сервер: GET http://127.0.0.1:8000/health. Жив = пришёл ЛЮБОЙ HTTP-ответ
  (200, 404, 401, 405…): значит uvicorn разобрал запрос и event loop не завис.
  Не жив = соединение отклонено или нет ответа за PROBE_TIMEOUT_MS.
  Это надёжнее голого TCP-connect: ядро Windows принимает TCP-соединение
  из backlog даже тогда, когда сам сервер висит.
  Запрос помечен User-Agent: SouronMCP-HealthCheck — middleware может его пропускать.
* Туннель: cloudflared запускается с --metrics 127.0.0.1:20241, а его эндпоинт /ready
  отвечает 200, только когда есть хотя бы одно активное соединение с сетью Cloudflare.
  Здесь наоборот требуем именно 200 (503 = процесс жив, но не подключён).
"""
from __future__ import annotations

from PyQt6.QtCore import QObject, QTimer, QUrl, pyqtSignal
from PyQt6.QtNetwork import (
    QNetworkAccessManager,
    QNetworkProxy,
    QNetworkReply,
    QNetworkRequest,
)

PROBE_TIMEOUT_MS = 1500
HEALTH_USER_AGENT = "SouronMCP-HealthCheck"


class HealthMonitor(QObject):
    server_health = pyqtSignal(bool)
    tunnel_health = pyqtSignal(bool)

    def __init__(self, host: str, port: int, metrics_port: int, health_path: str = "/health",
                 interval_ms: int = 2000, parent: QObject | None = None) -> None:
        super().__init__(parent)
        path = health_path if health_path.startswith("/") else f"/{health_path}"
        self._health_url = QUrl(f"http://{host}:{port}{path}")
        self._ready_url = QUrl(f"http://127.0.0.1:{metrics_port}/ready")

        self._nam = QNetworkAccessManager(self)
        self._nam.setProxy(QNetworkProxy(QNetworkProxy.ProxyType.NoProxy))  # localhost мимо системного прокси

        self._timer = QTimer(self)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self.probe_now)

        self._active = False
        self._server_reply: QNetworkReply | None = None
        self._tunnel_reply: QNetworkReply | None = None
        self.check_tunnel = False  # включает ServiceManager, когда туннель запущен

    @property
    def health_path(self) -> str:
        return self._health_url.path()

    def start(self) -> None:
        self._active = True
        if not self._timer.isActive():
            self._timer.start()
            QTimer.singleShot(300, self.probe_now)  # первая проверка почти сразу

    def stop(self) -> None:
        # _active=False до abort(): отменённые запросы не должны слать ложное «упал».
        self._active = False
        self._timer.stop()
        self.check_tunnel = False
        for reply in (self._server_reply, self._tunnel_reply):
            if reply is not None:
                reply.abort()

    def probe_now(self) -> None:
        if not self._active:
            return
        self._probe_server()
        if self.check_tunnel:
            self._probe_tunnel()

    # ------------------------------------------------------------------ server
    def _probe_server(self) -> None:
        if self._server_reply is not None:  # предыдущая проверка ещё идёт
            return
        reply = self._nam.get(self._request(self._health_url))
        self._server_reply = reply

        def on_finished() -> None:
            status = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
            self._server_reply = None
            reply.deleteLater()
            if self._active:
                # Статус есть (любой, включая 404) -> сервер ответил.
                # None -> отказ в соединении / таймаут / обрыв.
                self.server_health.emit(status is not None)

        reply.finished.connect(on_finished)

    # ------------------------------------------------------------------ tunnel
    def _probe_tunnel(self) -> None:
        if self._tunnel_reply is not None:
            return
        reply = self._nam.get(self._request(self._ready_url))
        self._tunnel_reply = reply

        def on_finished() -> None:
            status = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
            self._tunnel_reply = None
            reply.deleteLater()
            if self._active:
                self.tunnel_health.emit(status == 200)

        reply.finished.connect(on_finished)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _request(url: QUrl) -> QNetworkRequest:
        request = QNetworkRequest(url)
        request.setTransferTimeout(PROBE_TIMEOUT_MS)
        request.setRawHeader(b"User-Agent", HEALTH_USER_AGENT.encode())
        return request
