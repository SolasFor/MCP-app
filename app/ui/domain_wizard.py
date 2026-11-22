"""Мастер «Свой домен»: токен API + имя хоста → всё остальное делает cf_api.setup_domain.

Открывается кнопкой «Свой домен», когда домен ещё не настроен, или ссылкой «Настроить свой
домен…». Ручная инструкция (domain_guide) — только по ссылке «Как это работает»:
диалог шлёт guide_requested, инструкцию открывает главное окно.

Запросы к API — в фоновом потоке, через прокси из вкладки «Прокси» (если в списке
есть api.cloudflare.com:443). Токен API не сохраняется.
"""
from __future__ import annotations

import threading

from PyQt6.QtCore import Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget,
)

from app.core import cf_api, domain_state
from app.core import proxy as px

TOKEN_PAGE = "https://dash.cloudflare.com/profile/api-tokens"
PENDING, RUNNING, DONE, FAILED = "○", "…", "✓", "✕"


def _button(text: str, name: str | None = None) -> QPushButton:
    button = QPushButton(text)
    if name:
        button.setObjectName(name)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


class DomainWizard(QDialog):
    configured = pyqtSignal(object)   # domain_state.DomainState
    guide_requested = pyqtSignal()
    _step = pyqtSignal(int)
    _done = pyqtSignal(object)        # DomainResult | str (текст ошибки)

    def __init__(self, local_port: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Свой домен")
        self.setMinimumWidth(540)
        self._port = local_port
        self._current = -1
        self._busy = False

        intro = QLabel(
            "Постоянный адрес вида <b>mcp.example.com</b> вместо временного. Домен должен быть "
            "добавлен в Cloudflare. Туннель, DNS-запись и ключ приложение создаст само.")
        intro.setWordWrap(True)

        token_hint = QLabel(
            "Создайте токен: Create Token → Custom token, права: "
            + "; ".join(cf_api.TOKEN_PERMISSIONS)
            + ". Токен нужен один раз и не сохраняется.")
        token_hint.setWordWrap(True)
        token_hint.setObjectName("Hint")
        open_page = _button("Открыть страницу токенов →", "Link")
        open_page.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(TOKEN_PAGE)))

        self.hostname = QLineEdit(domain_state.load().hostname)
        self.hostname.setPlaceholderText("mcp.example.com")
        self.token = QLineEdit()
        self.token.setEchoMode(QLineEdit.EchoMode.Password)
        self.token.setPlaceholderText("токен API Cloudflare")
        form = QFormLayout()
        form.addRow("Адрес", self.hostname)
        form.addRow("Токен API", self.token)

        self._step_labels: list[QLabel] = []
        steps = QVBoxLayout()
        steps.setSpacing(4)
        for text in cf_api.SETUP_STEPS:
            label = QLabel(f"{PENDING}  {text}")
            label.setObjectName("Hint")
            self._step_labels.append(label)
            steps.addWidget(label)

        self.error = QLabel("")
        self.error.setObjectName("Error")
        self.error.setWordWrap(True)
        self.error.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.error.hide()

        manual = _button("Как это работает", "Link")
        manual.setToolTip("Пошаговая инструкция для ручной настройки через config.yml")
        manual.clicked.connect(self.guide_requested.emit)
        self.run_btn = _button("Настроить", "Accent")
        self.run_btn.setDefault(True)
        self.cancel_btn = _button("Отмена", "Ghost")
        self.cancel_btn.clicked.connect(self.reject)
        buttons = QHBoxLayout()
        buttons.addWidget(manual)
        buttons.addStretch(1)
        buttons.addWidget(self.cancel_btn)
        buttons.addWidget(self.run_btn)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(12)
        layout.addWidget(intro)
        layout.addWidget(token_hint)
        layout.addWidget(open_page, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addLayout(form)
        layout.addLayout(steps)
        layout.addWidget(self.error)
        layout.addLayout(buttons)

        self.run_btn.clicked.connect(self._run)
        self._step.connect(self._on_step)
        self._done.connect(self._on_done)

    def reject(self) -> None:
        if self._busy:
            return  # не закрываем посреди настройки: результат иначе потеряется
        super().reject()

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        for widget in (self.hostname, self.token, self.run_btn, self.cancel_btn):
            widget.setEnabled(not busy)

    def _show_error(self, text: str) -> None:
        self.error.setText(text)
        self.error.setVisible(bool(text))

    def _run(self) -> None:
        self._show_error("")
        try:
            host = cf_api.normalize_hostname(self.hostname.text())
            api = cf_api.CloudflareAPI(self.token.text(), px.load())
        except cf_api.CloudflareError as exc:
            self._show_error(str(exc))
            return
        self.hostname.setText(host)
        for label, text in zip(self._step_labels, cf_api.SETUP_STEPS):
            label.setText(f"{PENDING}  {text}")
        self._current = -1
        self._set_busy(True)

        def work() -> None:
            try:
                result = cf_api.setup_domain(api, host, self._port, self._step.emit)
            except cf_api.CloudflareError as exc:
                self._done.emit(str(exc))
            except OSError as exc:
                self._done.emit(f"Нет связи с api.cloudflare.com: {px.describe(exc)}. "
                                "Если он недоступен напрямую, включите прокси во вкладке «Прокси».")
            except Exception as exc:  # noqa: BLE001 — любая ошибка должна дойти до окна
                self._done.emit(f"Непредвиденная ошибка: {exc!r}")
            else:
                self._done.emit(result)

        threading.Thread(target=work, name="domain-setup", daemon=True).start()

    def _mark(self, index: int, mark: str) -> None:
        if 0 <= index < len(self._step_labels):
            self._step_labels[index].setText(f"{mark}  {cf_api.SETUP_STEPS[index]}")

    def _on_step(self, index: int) -> None:
        self._mark(self._current, DONE)
        self._current = index
        self._mark(index, RUNNING)

    def _on_done(self, outcome: object) -> None:
        self._set_busy(False)
        if isinstance(outcome, str):
            self._mark(self._current, FAILED)
            self._show_error(outcome)
            return
        self._mark(self._current, DONE)
        result: cf_api.DomainResult = outcome  # type: ignore[assignment]
        state = domain_state.DomainState(
            hostname=result.hostname, tunnel_id=result.tunnel_id,
            tunnel_token=result.tunnel_token, zone_name=result.zone_name)
        try:
            domain_state.save(state)
        except OSError as exc:
            self._show_error(f"Туннель создан, но ключ не сохранён: {exc}")
            return
        self.token.clear()
        self.configured.emit(state)
        self.accept()
