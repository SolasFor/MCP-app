"""Мастер «Свой домен»: два режима настройки Cloudflare Named Tunnel.

1. Автоматическая настройка по одноразовому Cloudflare API Token (создаёт туннель и DNS CNAME;
   API Token не сохраняется; сохраняется полученный Cloudflare Tunnel Token в SecretStore).
2. Подключение к уже существующему туннелю: пользователь указывает свой домен и готовый
   Cloudflare Tunnel Token (сохраняется в DPAPI SecretStore), без API Token и без изменения DNS.
"""
from __future__ import annotations

import base64
import json
import threading

from PyQt6.QtCore import Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.core import cf_api, domain_state
from app.core import proxy as px
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.silent_dialog import SilentDialog
from app.ui.i18n import tr

TOKEN_PAGE = "https://dash.cloudflare.com/profile/api-tokens"
PENDING, RUNNING, DONE, FAILED = "○", "…", "✓", "✕"


def _button(text: str, name: str | None = None) -> QPushButton:
    button = QPushButton(text)
    if name:
        button.setObjectName(name)
    if name in ("Link", "SubtleLink"):
        button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


def _extract_tunnel_id_from_token(token: str) -> str:
    """Decode Cloudflare Tunnel Token base64 JSON payload ``{"t": "<tunnel_id>"}`` if present."""
    clean = (token or "").strip()
    if not clean:
        return ""
    padded = clean + "=" * (-len(clean) % 4)
    try:
        raw = base64.b64decode(padded, validate=True).decode("utf-8")
        obj = json.loads(raw)
        if isinstance(obj, dict):
            tid = obj.get("t")
            if isinstance(tid, str) and tid.strip():
                return tid.strip()
    except Exception:  # noqa: BLE001
        pass
    return ""


class DomainWizard(SilentDialog):
    configured = pyqtSignal(object)   # domain_state.DomainState
    guide_requested = pyqtSignal()
    _step = pyqtSignal(int)
    _done = pyqtSignal(object)        # DomainResult | str (текст ошибки)
    _check_done = pyqtSignal(bool, str)

    def __init__(self, local_port: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Свой домен (Cloudflare Named Tunnel)")
        self.setMinimumWidth(580)
        self._port = local_port
        self._current = -1
        self._busy = False
        existing = domain_state.load()

        intro = QLabel(
            "Постоянный адрес вида <b>mcp.example.com</b> вместо временного. "
            "Не путайте ключи: здесь вводятся ключи Cloudflare, а не MCP Owner Token."
        )
        intro.setObjectName("Hint")
        intro.setWordWrap(True)

        self.mode_combo = SafeComboBox()
        self.mode_combo.addItem("Автонастройка через Cloudflare API Token (создать туннель и DNS)", "api")
        self.mode_combo.addItem("Существующий туннель: домен + Cloudflare Tunnel Token", "tunnel_token")
        mode_row = QFormLayout()
        mode_row.addRow("Режим настройки", self.mode_combo)

        self.hostname = QLineEdit(existing.hostname)
        self.hostname.setObjectName("UiInput")
        self.hostname.setPlaceholderText("mcp.example.com")
        host_form = QFormLayout()
        host_form.addRow("Адрес домена", self.hostname)

        self._pages = QStackedWidget()

        # --- Page 0: API Token (automatic)
        api_page = QWidget()
        api_box = QVBoxLayout(api_page)
        api_box.setContentsMargins(0, 0, 0, 0)
        api_box.setSpacing(8)
        token_hint = QLabel(
            "Создайте одноразовый API Token: Create Token → Custom token, права: "
            + "; ".join(cf_api.TOKEN_PERMISSIONS)
            + ". Cloudflare API Token не сохраняется; приложение сохранит только полученный Tunnel Token в SecretStore."
        )
        token_hint.setWordWrap(True)
        token_hint.setObjectName("Hint")
        open_page = _button("Открыть страницу токенов Cloudflare →", "Link")
        open_page.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(TOKEN_PAGE)))

        self.token = QLineEdit()
        self.token.setObjectName("UiInput")
        self.token.setEchoMode(QLineEdit.EchoMode.Password)
        self.token.setPlaceholderText("Cloudflare API Token (одноразовый)")
        self.api_token_eye = _button(tr("conn.token.show"), "Ghost")
        self.api_token_eye.clicked.connect(lambda: self._toggle_eye(self.token, self.api_token_eye))
        api_tok_row = QHBoxLayout()
        api_tok_row.addWidget(self.token, 1)
        api_tok_row.addWidget(self.api_token_eye)

        api_form = QFormLayout()
        api_form.addRow("Cloudflare API Token", api_tok_row)

        self._step_labels: list[QLabel] = []
        steps = QVBoxLayout()
        steps.setSpacing(4)
        for text in cf_api.SETUP_STEPS:
            label = QLabel(f"{PENDING}  {text}")
            label.setObjectName("Hint")
            self._step_labels.append(label)
            steps.addWidget(label)

        api_box.addWidget(token_hint)
        api_box.addWidget(open_page, 0, Qt.AlignmentFlag.AlignLeft)
        api_box.addLayout(api_form)
        api_box.addLayout(steps)

        # --- Page 1: Existing Tunnel Token (no API token / no DNS changes)
        tt_page = QWidget()
        tt_box = QVBoxLayout(tt_page)
        tt_box.setContentsMargins(0, 0, 0, 0)
        tt_box.setSpacing(8)
        tt_hint = QLabel(
            "Если туннель и CNAME-запись уже созданы в Cloudflare Zero Trust вручную, "
            "вставьте готовый Cloudflare Tunnel Token (токен из команды cloudflared service install). "
            "API Token не требуется, туннель и DNS не пересоздаются."
        )
        tt_hint.setWordWrap(True)
        tt_hint.setObjectName("Hint")

        self.tunnel_token_edit = QLineEdit()
        self.tunnel_token_edit.setObjectName("UiInput")
        self.tunnel_token_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.tunnel_token_edit.setPlaceholderText(
            "Уже сохранён в SecretStore (оставьте пустым, чтобы не менять)"
            if existing.tunnel_token
            else "Вставьте Cloudflare Tunnel Token (DPAPI)"
        )
        self.tunnel_token_eye = _button(tr("conn.token.show"), "Ghost")
        self.tunnel_token_eye.clicked.connect(
            lambda: self._toggle_eye(self.tunnel_token_edit, self.tunnel_token_eye)
        )
        tt_row = QHBoxLayout()
        tt_row.addWidget(self.tunnel_token_edit, 1)
        tt_row.addWidget(self.tunnel_token_eye)
        tt_form = QFormLayout()
        tt_form.addRow("Cloudflare Tunnel Token", tt_row)

        self.check_avail_btn = _button("Проверить доступность домена и Cloudflare", "Ghost")
        self.check_avail_btn.clicked.connect(self._check_existing_availability)
        self.avail_label = QLabel("")
        self.avail_label.setObjectName("Hint")
        self.avail_label.setWordWrap(True)

        tt_box.addWidget(tt_hint)
        tt_box.addLayout(tt_form)
        tt_box.addWidget(self.check_avail_btn, 0, Qt.AlignmentFlag.AlignLeft)
        tt_box.addWidget(self.avail_label)
        tt_box.addStretch(1)

        self._pages.addWidget(api_page)
        self._pages.addWidget(tt_page)

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
        buttons.setSpacing(6)
        buttons.addWidget(manual)
        buttons.addStretch(1)
        buttons.addWidget(self.cancel_btn)
        buttons.addWidget(self.run_btn)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)
        layout.addWidget(intro)
        layout.addLayout(mode_row)
        layout.addLayout(host_form)
        layout.addWidget(self._pages)
        layout.addWidget(self.error)
        layout.addLayout(buttons)

        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        self.run_btn.clicked.connect(self._run)
        self._step.connect(self._on_step)
        self._done.connect(self._on_done)
        self._check_done.connect(self._on_availability_checked)

        if existing.setup_mode == "tunnel_token" or (existing.tunnel_token and not existing.zone_name):
            self.mode_combo.setCurrentIndex(1)
            self._on_mode_changed(1)

    @staticmethod
    def _toggle_eye(edit: QLineEdit, btn: QPushButton) -> None:
        vis = edit.echoMode() == QLineEdit.EchoMode.Password
        edit.setEchoMode(QLineEdit.EchoMode.Normal if vis else QLineEdit.EchoMode.Password)
        btn.setText(tr("conn.token.hide" if vis else "conn.token.show"))

    def current_mode(self) -> str:
        return str(self.mode_combo.currentData() or "api")

    def _on_mode_changed(self, _index: int) -> None:
        mode = self.current_mode()
        self._pages.setCurrentIndex(1 if mode == "tunnel_token" else 0)
        self.run_btn.setText("Сохранить и подключить" if mode == "tunnel_token" else "Настроить")
        self._show_error("")

    def reject(self) -> None:
        if self._busy:
            return  # не закрываем посреди настройки: результат иначе потеряется
        super().reject()

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        for widget in (
            self.mode_combo,
            self.hostname,
            self.token,
            self.tunnel_token_edit,
            self.check_avail_btn,
            self.run_btn,
            self.cancel_btn,
        ):
            widget.setEnabled(not busy)

    def _show_error(self, text: str) -> None:
        self.error.setText(text)
        self.error.setVisible(bool(text))

    def _check_existing_availability(self) -> None:
        self._show_error("")
        try:
            host = cf_api.normalize_hostname(self.hostname.text())
        except cf_api.CloudflareError as exc:
            self._show_error(str(exc))
            return
        self.hostname.setText(host)
        self.check_avail_btn.setEnabled(False)
        self.avail_label.setText("Проверяю edge Cloudflare и домен…")

        def work() -> None:
            proxy_cfg = px.load()
            edge_ok, edge_msg, _ = px.diagnose_target(
                proxy_cfg, "region1.v2.argotunnel.com", 7844, via_proxy=proxy_cfg.enabled
            )
            dom_ok, dom_msg, _ = px.diagnose_target(proxy_cfg, host, 443, via_proxy=False)
            if not edge_ok:
                self._check_done.emit(
                    False,
                    f"Проблема связи с Cloudflare Edge: {edge_msg}. "
                    "Проверьте настройки прокси, если требуется обход блокировок.",
                )
            elif not dom_ok:
                self._check_done.emit(
                    True,
                    f"Cloudflare Edge доступен ({edge_msg}). "
                    f"Примечание по {host}: {dom_msg} (появится после запуска cloudflared и настройки DNS).",
                )
            else:
                self._check_done.emit(
                    True,
                    f"Cloudflare Edge ({edge_msg}) и {host}:443 ({dom_msg}) доступны.",
                )

        threading.Thread(target=work, name="domain-avail-check", daemon=True).start()

    def _on_availability_checked(self, _ok: bool, text: str) -> None:
        self.check_avail_btn.setEnabled(True)
        self.avail_label.setText(text)

    def _run(self) -> None:
        self._show_error("")
        if self.current_mode() == "tunnel_token":
            self._save_existing_tunnel_token()
            return
        try:
            host = cf_api.normalize_hostname(self.hostname.text())
            api = cf_api.CloudflareAPI(self.token.text(), px.load())
        except cf_api.CloudflareError as exc:
            self._show_error(str(exc))
            return
        self.hostname.setText(host)
        for label, text in zip(self._step_labels, cf_api.SETUP_STEPS, strict=True):
            label.setText(f"{PENDING}  {text}")
        self._current = -1
        self._set_busy(True)

        def work() -> None:
            try:
                result = cf_api.setup_domain(api, host, self._port, self._step.emit)
            except cf_api.CloudflareError as exc:
                self._done.emit(str(exc))
            except OSError as exc:
                self._done.emit(
                    f"Нет связи с api.cloudflare.com: {px.describe(exc)}. "
                    "Если он недоступен напрямую, включите прокси во вкладке «Прокси»."
                )
            except Exception as exc:  # noqa: BLE001
                self._done.emit(f"Непредвиденная ошибка: {exc!r}")
            else:
                self._done.emit(result)

        threading.Thread(target=work, name="domain-setup", daemon=True).start()

    def _save_existing_tunnel_token(self) -> None:
        try:
            host = cf_api.normalize_hostname(self.hostname.text())
        except cf_api.CloudflareError as exc:
            self._show_error(str(exc))
            return
        existing = domain_state.load()
        raw_token = self.tunnel_token_edit.text().strip() or existing.tunnel_token
        if not raw_token:
            self._show_error("Укажите Cloudflare Tunnel Token для подключения к существующему туннелю.")
            return
        if len(raw_token) < 16 or any(ch.isspace() for ch in raw_token):
            self._show_error("Некорректный формат Cloudflare Tunnel Token.")
            return
        tunnel_id = _extract_tunnel_id_from_token(raw_token) or existing.tunnel_id
        state = domain_state.DomainState(
            hostname=host,
            tunnel_id=tunnel_id,
            tunnel_token=raw_token,
            zone_name=existing.zone_name,
            setup_mode="tunnel_token",
            public_url=f"https://{host}",
        )
        try:
            domain_state.save(state)
        except OSError as exc:
            self._show_error(f"Не удалось сохранить домен и Tunnel Token: {exc}")
            return
        self.tunnel_token_edit.clear()
        self.configured.emit(state)
        self.accept()

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
            hostname=result.hostname,
            tunnel_id=result.tunnel_id,
            tunnel_token=result.tunnel_token,
            zone_name=result.zone_name,
            setup_mode="api",
            public_url=f"https://{result.hostname}",
        )
        try:
            domain_state.save(state)
        except OSError as exc:
            self._show_error(f"Туннель создан, но ключ не сохранён: {exc}")
            return
        self.token.clear()
        self.configured.emit(state)
        self.accept()
