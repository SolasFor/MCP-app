"""Non-blocking connection diagnostics dialog with redacted report export."""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app import __version__
from app.core.diagnostics import (
    ProbeResult,
    build_diagnostic_report,
    export_diagnostic_report,
    probe_connection,
)
from app.paths import user_data_dir
from app.ui.components.silent_dialog import SilentDialog, SilentMessageBox


class DiagnosticWorker(QThread):
    results_ready = pyqtSignal(object)

    def __init__(
        self,
        public_url: str,
        local_port: int,
        health_path: str,
        owner_token: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.public_url = public_url
        self.local_port = local_port
        self.health_path = health_path
        self.owner_token = owner_token

    def run(self) -> None:
        try:
            results = probe_connection(
                self.public_url,
                self.local_port,
                self.health_path,
                self.owner_token,
            )
        except Exception as error:
            results = [
                ProbeResult(
                    "Диагностика",
                    False,
                    f"Непредвиденная ошибка: {type(error).__name__}",
                )
            ]
        finally:
            self.owner_token = ""
        self.results_ready.emit(results)


class ConnectionDiagnosticsDialog(SilentDialog):
    def __init__(
        self,
        public_url: str,
        port: int,
        health_path: str,
        owner_token: str,
        parent: QWidget | None = None,
        *,
        tunnel_mode: str = "",
        tunnel_protocol: str = "",
        recent_logs: tuple[str, ...] = (),
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Проверка MCP-подключения")
        self.resize(660, 455)
        self._worker: DiagnosticWorker | None = None
        self._params = (public_url, port, health_path)
        self._initial_token = owner_token
        self._results: list[ProbeResult] = []
        self._tunnel_mode = tunnel_mode
        self._tunnel_protocol = tunnel_protocol
        self._recent_logs = list(recent_logs)
        self._secrets_for_redaction = [owner_token] if owner_token else []

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)
        title = QLabel("Диагностика MCP и OAuth")
        title.setObjectName("SectionTitle")
        root.addWidget(title)
        summary = QLabel(
            "Проверяются локальный HTTP-сервер, публичный адрес Cloudflare, "
            "OAuth-метаданные и локальный MCP initialize. "
            "Токен владельца отправляется только на 127.0.0.1; "
            "через публичный адрес он не передаётся."
        )
        summary.setObjectName("Hint")
        summary.setWordWrap(True)
        root.addWidget(summary)

        self.details = QTextEdit()
        self.details.setObjectName("ConsoleLog")
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Результаты проверок появятся здесь.")
        root.addWidget(self.details, 1)
        self.status = QLabel("")
        self.status.setObjectName("Hint")
        root.addWidget(self.status)

        footer = QHBoxLayout()
        footer.setSpacing(6)
        self.start_button = QPushButton("Запустить проверки")
        self.start_button.setObjectName("Accent")
        self.start_button.clicked.connect(self.start_checks)
        self.save_report_button = QPushButton("Сохранить отчёт…")
        self.save_report_button.setObjectName("Ghost")
        self.save_report_button.setEnabled(False)
        self.save_report_button.clicked.connect(self.save_report)
        self.close_button = QPushButton("Закрыть")
        self.close_button.setObjectName("Ghost")
        self.close_button.clicked.connect(self.accept)
        footer.addWidget(self.start_button)
        footer.addWidget(self.save_report_button)
        footer.addStretch()
        footer.addWidget(self.close_button)
        root.addLayout(footer)
        self.start_checks()

    def start_checks(self) -> None:
        if self._worker is not None:
            return
        self.start_button.setEnabled(False)
        self.save_report_button.setEnabled(False)
        self.close_button.setEnabled(False)
        self.status.setText("Проверка выполняется без блокировки окна…")
        self.details.clear()
        self._worker = DiagnosticWorker(
            *self._params,
            self._initial_token,
            self,
        )
        self._initial_token = ""
        self._worker.results_ready.connect(self._display_results)
        self._worker.finished.connect(self._finish)
        self._worker.start()

    def _display_results(self, results: list[ProbeResult]) -> None:
        self._results = list(results)
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
        self.save_report_button.setEnabled(bool(self._results))
        self.close_button.setEnabled(True)

    def save_report(self) -> None:
        default_path = str(user_data_dir() / "diagnostic-report.json")
        dest, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить защищённый диагностический отчёт",
            default_path,
            "JSON (*.json)",
        )
        if not dest:
            return
        public_url, port, health_path = self._params
        report = build_diagnostic_report(
            app_version=__version__,
            public_url=public_url,
            local_port=port,
            health_path=health_path,
            tunnel_mode=self._tunnel_mode,
            tunnel_protocol=self._tunnel_protocol,
            probe_results=self._results,
            recent_logs=self._recent_logs,
            secrets_to_redact=self._secrets_for_redaction,
        )
        try:
            export_diagnostic_report(Path(dest), report)
        except OSError as exc:
            SilentMessageBox.warning(
                self, "Диагностика", f"Не удалось сохранить отчёт: {type(exc).__name__}"
            )
            return
        SilentMessageBox.information(
            self,
            "Диагностика",
            "Отчёт сохранён. Секретные токены и ключи исключены из файла.",
        )

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
