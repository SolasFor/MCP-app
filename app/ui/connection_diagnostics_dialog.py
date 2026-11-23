"""Non-blocking connection diagnostics dialog for the MCP app GUI."""
from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QPushButton, QTextEdit, QVBoxLayout, QWidget,
)

from app.core.diagnostics import ProbeResult, probe_connection


class DiagnosticWorker(QThread):
    results_ready = pyqtSignal(object)

    def __init__(
        self, public_url: str, local_port: int, health_path: str,
        owner_token: str, parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.public_url = public_url
        self.local_port = local_port
        self.health_path = health_path
        self.owner_token = owner_token

    def run(self) -> None:
        try:
            results = probe_connection(
                self.public_url, self.local_port,
                self.health_path, self.owner_token,
            )
        except Exception as error:
            results = [ProbeResult(
                "Диагностика", False,
                f"Непредвиденная ошибка: {type(error).__name__}",
            )]
        finally:
            # Do not retain the owner token in a long-lived Qt object.
            self.owner_token = ""
        self.results_ready.emit(results)


class ConnectionDiagnosticsDialog(QDialog):
    def __init__(
        self, public_url: str, port: int, health_path: str,
        owner_token: str, parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Проверка MCP-подключения")
        self.resize(660, 455)
        self._worker: DiagnosticWorker | None = None
        # Do not keep the token as a property on this dialog.
        self._params = (public_url, port, health_path)
        self._initial_token = owner_token

        root = QVBoxLayout(self)
        title = QLabel("Диагностика MCP и OAuth")
        title.setObjectName("SectionTitle")
        root.addWidget(title)
        summary = QLabel(
            "Проверяются локальный HTTP-сервер, публичный адрес Cloudflare, "
            "OAuth-метаданные и локальный MCP initialize. "
            "Токен владельца отправляется только на 127.0.0.1; "
            "через публичный адрес он не передаётся."
        )
        summary.setWordWrap(True)
        root.addWidget(summary)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Результаты проверок появятся здесь.")
        root.addWidget(self.details, 1)
        self.status = QLabel("")
        root.addWidget(self.status)

        footer = QHBoxLayout()
        self.start_button = QPushButton("Запустить проверки")
        self.start_button.clicked.connect(self.start_checks)
        self.close_button = QPushButton("Закрыть")
        self.close_button.clicked.connect(self.accept)
        footer.addWidget(self.start_button)
        footer.addStretch()
        footer.addWidget(self.close_button)
        root.addLayout(footer)
        self.start_checks()

    def start_checks(self) -> None:
        if self._worker is not None:
            return
        self.start_button.setEnabled(False)
        self.close_button.setEnabled(False)
        self.status.setText("Проверка выполняется без блокировки окна…")
        self.details.clear()
        # The GUI may contain an owner token in memory; only the worker gets
        # a short-lived copy and clears it after use.
        self._worker = DiagnosticWorker(
            *self._params, self._initial_token, self,
        )
        self._initial_token = ""
        self._worker.results_ready.connect(self._display_results)
        self._worker.finished.connect(self._finish)
        self._worker.start()

    def _display_results(self, results: list[ProbeResult]) -> None:
        for item in results:
            marker = "✓" if item.passed else "✖"
            self.details.append(f"{marker} {item.label}: {item.message}")
        passed = sum(item.passed for item in results)
        self.status.setText(f"Успешно: {passed} из {len(results)}")
        if passed != len(results):
            self.details.append(
                "\nЕсли публичный HTTP недоступен, проверьте cloudflared /ready и "
                "совпадение текущего адреса trycloudflare.com. "
                "Отдельные cloudflared 'context canceled' сами по себе "
                "не доказывают сбой туннеля."
            )

    def _finish(self) -> None:
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.deleteLater()
        self.start_button.setEnabled(False)  # session token intentionally erased
        self.close_button.setEnabled(True)

    def reject(self) -> None:
        if self._worker is not None:
            self.status.setText("Проверка HTTP выполняется, окно закроется после завершения.")
            return
        super().reject()

    def accept(self) -> None:
        if self._worker is not None:
            self.status.setText("Проверка HTTP выполняется, окно закроется после завершения.")
            return
        super().accept()

    def closeEvent(self, event) -> None:  # noqa: N802
        if self._worker is not None:
            event.ignore()
            self.status.setText("Проверка HTTP выполняется, окно закроется после завершения.")
            return
        super().closeEvent(event)
