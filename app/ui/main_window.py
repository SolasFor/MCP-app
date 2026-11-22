"""Главное окно SouronMCP.

    Шапка        логотип, название, общий статус (точка + подпись с бликом во время процесса)
    Сервисы      «Запустить / Остановить», состояние сервера и туннеля
    Подключение  режим туннеля, публичный адрес, токен доступа
    Параметры    автозапуск, старт сервисов, трей
    Журнал       сворачивается, счётчик непросмотренных ошибок

Окно только показывает состояние и передаёт команды. Проверка и применение
настроек (в том числе перезапуск сервисов) — в ServiceManager.
"""
from __future__ import annotations

import re
import sys
from urllib.parse import urlsplit

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QCloseEvent, QGuiApplication, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app import APP_NAME
from app.config import TUNNEL_NAMED, TUNNEL_QUICK, Settings
from app.core import autostart, token_store
from app.core.process import ProcState
from app.core.service_manager import APP, Overall, ServiceManager
from app.ui import effects, icons, theme
from app.ui.widgets import LogView, StatusDot, StatusRow

LOG_HEIGHT = 280
FLASH_MS = 1500
_QUERY_TOKEN_RE = re.compile(r"(token=)[^&\s\"']+")

NAMED_HINT = (
    "Постоянный адрес через ваш туннель из ~/.cloudflared/config.yml. "
    "Для нового домена добавьте его в ingress config.yml и создайте DNS-запись: "
    "cloudflared tunnel route dns <туннель> <домен>."
)
QUICK_HINT = (
    "Не нужны домен и аккаунт Cloudflare. Адрес *.trycloudflare.com выдаётся заново "
    "при каждом запуске туннеля — обновляйте его в клиентах. Это режим для пробы и тестов: "
    "Cloudflare не даёт гарантий, ограничивает число одновременных запросов и не передаёт SSE."
)
TOKEN_HINT = "Клиенты передают его в заголовке Authorization: Bearer <токен>. Хранится только на этом компьютере."


# ====================================================================== helpers
def _repolish(widget: QWidget) -> None:
    """Переприменить QSS после смены динамического свойства (running, invalid)."""
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


def _label(text: str, name: str, wrap: bool = False) -> QLabel:
    label = QLabel(text)
    label.setObjectName(name)
    label.setWordWrap(wrap)
    return label


def _button(text: str, name: str | None = None, tooltip: str = "") -> QPushButton:
    button = QPushButton(text)
    if name:
        button.setObjectName(name)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    if tooltip:
        button.setToolTip(tooltip)
    return button


def _card() -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("Card")
    box = QVBoxLayout(frame)
    box.setContentsMargins(20, 18, 20, 20)
    box.setSpacing(10)
    return frame, box


def _divider() -> QFrame:
    line = QFrame()
    line.setObjectName("Divider")
    return line


# ====================================================================== окно
class MainWindow(QMainWindow):
    quit_requested = pyqtSignal()
    hidden_to_tray = pyqtSignal()

    def __init__(self, manager: ServiceManager, settings: Settings,
                 tray_available: bool = True, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.manager = manager
        self.settings = settings
        self._tray_available = tray_available
        self._allow_close = False
        self._tray_hint_shown = False
        self._unseen_errors = 0

        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(icons.app_icon())
        self.setMinimumSize(620, 560)
        self.resize(700, 900)

        content = QWidget()
        content.setObjectName("Root")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(16)
        self._layout = layout

        layout.addLayout(self._build_header())
        layout.addWidget(self._build_control_card())
        layout.addWidget(self._build_connection_card())
        layout.addWidget(self._build_options_card())
        layout.addWidget(self._build_logs())
        self._logs_index = layout.count() - 1
        layout.addStretch(0)
        self._spacer_index = layout.count() - 1

        scroll = QScrollArea()
        scroll.setObjectName("Scroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(content)
        self.setCentralWidget(scroll)

        manager.overall_state_changed.connect(self._on_overall)
        manager.service_state_changed.connect(lambda *_: self._refresh_services())
        manager.log_line.connect(self._log_view.append_line)
        manager.public_url_changed.connect(self._on_public_url)
        manager.token_changed.connect(self._on_token_changed)
        manager.settings_changed.connect(self._refresh_mode)
        self._log_view.set_redactor(self._redact)
        self._log_view.error_logged.connect(self._on_error_logged)

        QShortcut(QKeySequence("Ctrl+Q"), self, activated=self.quit_requested.emit)

        self._refresh_mode()
        self._load_token_into_field()
        self._on_overall(manager.overall)
        self._set_logs_expanded(settings.logs_expanded, animate=False)
        self._apply_dark_titlebar()

    # ================================================================== построение
    def _build_header(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(12)

        logo = QLabel()
        logo.setPixmap(icons.app_icon().pixmap(36, 36))
        row.addWidget(logo)

        titles = QVBoxLayout()
        titles.setSpacing(0)
        titles.addWidget(_label(APP_NAME, "AppTitle"))
        titles.addWidget(_label("MCP-сервер через Cloudflare Tunnel", "AppSubtitle"))
        row.addLayout(titles)
        row.addStretch(1)

        pill = QFrame()
        pill.setObjectName("Pill")
        pill_row = QHBoxLayout(pill)
        pill_row.setContentsMargins(6, 4, 14, 4)
        pill_row.setSpacing(4)
        self._pill_dot = StatusDot()
        self._pill_text = effects.ShinyLabel("")
        self._pill_text.setObjectName("PillText")
        pill_row.addWidget(self._pill_dot)
        pill_row.addWidget(self._pill_text)
        row.addWidget(pill, 0, Qt.AlignmentFlag.AlignVCenter)
        return row

    def _build_control_card(self) -> QFrame:
        card = effects.SpotlightFrame()
        box = QVBoxLayout(card)
        box.setContentsMargins(20, 18, 20, 18)
        box.setSpacing(14)

        top = QHBoxLayout()
        top.setSpacing(16)
        texts = QVBoxLayout()
        texts.setSpacing(4)
        texts.addWidget(_label("Сервисы", "SectionTitle"))
        self._control_hint = _label("", "Hint", wrap=True)
        texts.addWidget(self._control_hint)
        top.addLayout(texts, 1)

        self._toggle = effects.SparkButton("Запустить")
        self._toggle.setObjectName("Primary")
        self._toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self._toggle.setMinimumWidth(176)
        self._toggle.clicked.connect(self.manager.toggle)
        top.addWidget(self._toggle, 0, Qt.AlignmentFlag.AlignVCenter)
        box.addLayout(top)

        box.addWidget(_divider())
        self._server_row = StatusRow("MCP-сервер")
        self._tunnel_row = StatusRow("Cloudflare Tunnel")
        box.addWidget(self._server_row)
        box.addWidget(self._tunnel_row)
        return card

    def _build_connection_card(self) -> QFrame:
        card, box = _card()

        head = QHBoxLayout()
        head.addWidget(_label("Подключение", "SectionTitle"))
        head.addStretch(1)
        segment = QFrame()
        segment.setObjectName("SegmentGroup")
        seg_row = QHBoxLayout(segment)
        seg_row.setContentsMargins(3, 3, 3, 3)
        seg_row.setSpacing(2)
        self._mode_group = QButtonGroup(self)
        self._mode_group.setExclusive(True)
        self._mode_buttons: dict[str, QPushButton] = {}
        modes = (
            (TUNNEL_NAMED, "Свой домен", "Постоянный адрес через именованный туннель (config.yml)"),
            (TUNNEL_QUICK, "Временный адрес", "Без домена и аккаунта: случайный адрес *.trycloudflare.com"),
        )
        for mode, text, tip in modes:
            button = _button(text, "Segment", tip)
            button.setCheckable(True)
            button.clicked.connect(lambda _checked=False, m=mode: self._on_mode_clicked(m))
            self._mode_group.addButton(button)
            self._mode_buttons[mode] = button
            seg_row.addWidget(button)
        head.addWidget(segment)
        box.addLayout(head)

        self._mode_hint = _label("", "Hint", wrap=True)
        box.addWidget(self._mode_hint)
        box.addSpacing(6)

        # --- публичный адрес
        box.addWidget(_label("Публичный адрес", "FieldLabel"))
        url_row = QHBoxLayout()
        url_row.setSpacing(8)
        self._url_edit = QLineEdit()
        self._url_edit.textEdited.connect(self._on_url_edited)
        self._url_edit.returnPressed.connect(self._save_url)
        self._url_save = _button("Сохранить", "Accent", "Сохранить адрес (Enter)")
        self._url_save.clicked.connect(self._save_url)
        self._url_save.hide()
        self._url_copy = _button("Копировать")
        self._url_copy.clicked.connect(lambda: self._copy(self.manager.public_url, self._url_copy))
        url_row.addWidget(self._url_edit, 1)
        url_row.addWidget(self._url_save)
        url_row.addWidget(self._url_copy)
        box.addLayout(url_row)
        self._url_error = _label("", "Error", wrap=True)
        self._url_error.hide()
        box.addWidget(self._url_error)
        box.addSpacing(6)

        # --- токен
        box.addWidget(_label("Токен доступа", "FieldLabel"))
        token_row = QHBoxLayout()
        token_row.setSpacing(8)
        self._token_edit = QLineEdit()
        self._token_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._token_edit.setPlaceholderText(f"Не менее {token_store.MIN_LENGTH} символов")
        self._token_edit.textEdited.connect(self._on_token_edited)
        self._token_edit.returnPressed.connect(self._save_token)
        self._token_eye = _button("Показать", "Ghost")
        self._token_eye.clicked.connect(
            lambda: self._set_token_visible(self._token_edit.echoMode() == QLineEdit.EchoMode.Password)
        )
        self._token_save = _button("Сохранить", "Accent", "Сохранить токен (Enter)")
        self._token_save.clicked.connect(self._save_token)
        self._token_save.hide()
        self._token_copy = _button("Копировать")
        self._token_copy.clicked.connect(lambda: self._copy(self.manager.token, self._token_copy))
        self._token_gen = _button("Сгенерировать", tooltip="Новый случайный токен (32 символа)")
        self._token_gen.clicked.connect(self._generate_token)
        token_row.addWidget(self._token_edit, 1)
        token_row.addWidget(self._token_eye)
        token_row.addWidget(self._token_save)
        token_row.addWidget(self._token_copy)
        token_row.addWidget(self._token_gen)
        box.addLayout(token_row)
        self._token_error = _label("", "Error", wrap=True)
        self._token_error.hide()
        box.addWidget(self._token_error)
        box.addWidget(_label(TOKEN_HINT, "Hint", wrap=True))
        box.addSpacing(2)

        # --- токен в ссылке
        query_row = QHBoxLayout()
        self._query_check = QCheckBox("Разрешить токен в ссылке (?token=…)")
        self._query_check.setToolTip(
            "Для клиентов, в которых нельзя задать заголовок Authorization.\n"
            "Ссылка с токеном работает как пароль — не публикуйте её."
        )
        self._query_check.toggled.connect(self._on_query_toggled)
        self._copy_full = _button("Копировать ссылку с токеном", "Ghost")
        self._copy_full.clicked.connect(lambda: self._copy(self.manager.url_with_token(), self._copy_full))
        query_row.addWidget(self._query_check)
        query_row.addStretch(1)
        query_row.addWidget(self._copy_full)
        box.addLayout(query_row)
        return card

    def _build_options_card(self) -> QFrame:
        card, box = _card()
        box.setSpacing(6)
        box.addWidget(_label("Параметры", "SectionTitle"))
        box.addSpacing(4)

        self._autostart = QCheckBox("Запускать вместе с Windows")
        self._autostart.setEnabled(autostart.is_supported())
        self._autostart.setChecked(autostart.is_enabled())
        self._autostart.toggled.connect(self._on_autostart)

        self._start_on_launch = QCheckBox("Сразу запускать сервер и туннель при старте приложения")
        self._start_on_launch.setChecked(self.settings.start_services_on_launch)
        self._start_on_launch.toggled.connect(self._on_start_on_launch)

        self._minimize = QCheckBox("Сворачивать в трей при закрытии окна")
        self._minimize.setEnabled(self._tray_available)
        self._minimize.setChecked(self._tray_available and self.settings.minimize_to_tray_on_close)
        self._minimize.toggled.connect(self._on_minimize_toggled)

        for check in (self._autostart, self._start_on_launch, self._minimize):
            check.setCursor(Qt.CursorShape.PointingHandCursor)
            box.addWidget(check)
        return card

    def _build_logs(self) -> QWidget:
        section = QWidget()
        column = QVBoxLayout(section)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(8)

        head = QHBoxLayout()
        head.setSpacing(8)
        self._logs_toggle = _button("", "Disclosure")
        self._logs_toggle.clicked.connect(lambda: self._set_logs_expanded(not self.settings.logs_expanded))
        self._error_badge = _label("", "Badge")
        self._error_badge.hide()
        self._logs_copy = _button("Копировать", "Ghost")
        self._logs_copy.clicked.connect(lambda: self._copy(self._log_view.plain_text(), self._logs_copy))
        self._logs_clear = _button("Очистить", "Ghost")
        head.addWidget(self._logs_toggle)
        head.addWidget(self._error_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addStretch(1)
        head.addWidget(self._logs_copy)
        head.addWidget(self._logs_clear)
        column.addLayout(head)

        self._log_view = LogView()
        self._logs_clear.clicked.connect(self._log_view.clear_log)
        column.addWidget(self._log_view, 1)
        return section

    # ================================================================== статусы
    def _on_overall(self, state: Overall) -> None:
        text, color = theme.OVERALL[state.value]
        pending = state.value in theme.PENDING
        self._pill_dot.set_state(color, pending)
        self._pill_text.setText(text)
        self._pill_text.setStyleSheet(f"color: {color};")
        self._pill_text.set_base_color(color)
        self._pill_text.set_shine(pending)

        active = self.manager.is_active
        self._toggle.setText("Остановить" if active else "Запустить")
        self._toggle.setProperty("running", active)
        _repolish(self._toggle)
        self._toggle.setEnabled(active or state != Overall.STOPPING)

        self._update_control_hint(state)
        self._refresh_services()
        if state == Overall.ERROR and not self.settings.logs_expanded:
            self._set_logs_expanded(True)

    def _update_control_hint(self, state: Overall) -> None:
        quick = self.settings.is_quick_tunnel
        if state == Overall.RUNNING:
            hint = "Доступ открыт — клиенты подключаются по адресу ниже."
        elif state == Overall.STARTING:
            if quick and not self.manager.public_url:
                hint = "Жду временный адрес от Cloudflare…"
            else:
                hint = "Поднимаю сервер и туннель…"
        elif state == Overall.DEGRADED:
            hint = "Связь потеряна — переподключаюсь…"
        elif state == Overall.STOPPING:
            hint = "Останавливаю сервисы…"
        elif state == Overall.ERROR:
            hint = "Не удалось запустить — причина в журнале ниже."
        else:
            hint = "Нажмите «Запустить», чтобы открыть доступ к серверу из интернета."
        self._control_hint.setText(hint)

    def _refresh_services(self) -> None:
        m, s = self.manager, self.settings
        quick = s.is_quick_tunnel
        self._apply_row(
            self._server_row, m.server.state,
            waiting=m.is_active and quick and m.server.state == ProcState.STOPPED,
            waiting_text="Ждёт адрес…",
        )
        self._apply_row(
            self._tunnel_row, m.tunnel.state,
            waiting=m.is_active and not quick and m.tunnel.state == ProcState.STOPPED,
            waiting_text="Ждёт сервер…",
        )
        self._server_row.set_detail(f"{s.local_host()}:{s.server_port}")
        host = urlsplit(m.public_url).hostname if m.public_url else ""
        detail = host or ("временный адрес *.trycloudflare.com" if quick else "—")
        protocol = s.tunnel_protocol.strip()
        self._tunnel_row.set_detail(f"{detail}  ·  {protocol}" if protocol else detail)

    @staticmethod
    def _apply_row(row: StatusRow, state: ProcState, waiting: bool, waiting_text: str) -> None:
        if waiting:
            row.set_state(waiting_text, theme.WARN, pending=True)
            return
        text, color = theme.SERVICE[state.value]
        row.set_state(text, color, pending=state in (ProcState.STARTING, ProcState.STOPPING))

    # ================================================================== режим и адрес
    def _on_mode_clicked(self, mode: str) -> None:
        if mode == self.settings.tunnel_mode:
            return
        if self.manager.is_active and not self._confirm(
            "Сменить режим туннеля?",
            "Сервисы перезапустятся, а клиентам понадобится новый адрес.",
        ):
            self._refresh_mode()  # вернуть выделение на текущий режим
            return
        self.manager.set_tunnel_mode(mode)  # settings_changed -> _refresh_mode

    def _refresh_mode(self) -> None:
        s = self.settings
        quick = s.is_quick_tunnel
        self._mode_buttons[s.tunnel_mode].setChecked(True)
        self._mode_hint.setText(QUICK_HINT if quick else NAMED_HINT)
        self._url_edit.setReadOnly(quick)
        self._url_edit.setPlaceholderText("Появится после запуска туннеля" if quick else "mcp.example.com")
        self._url_edit.setToolTip("" if quick else "Можно ввести только домен — https:// и /mcp добавятся сами")
        self._url_edit.setText(self.manager.public_url)
        self._url_save.hide()
        self._set_field_error(self._url_edit, self._url_error, None)
        self._query_check.blockSignals(True)
        self._query_check.setChecked(s.allow_query_token)
        self._query_check.blockSignals(False)
        self._refresh_copy_buttons()
        self._refresh_services()
        self._update_control_hint(self.manager.overall)

    def _on_public_url(self, url: str) -> None:
        # Не затираем адрес, который пользователь прямо сейчас редактирует.
        if self.settings.is_quick_tunnel or not self._url_save.isVisible():
            self._url_edit.setText(url)
        self._refresh_copy_buttons()
        self._refresh_services()
        self._update_control_hint(self.manager.overall)

    def _on_url_edited(self, text: str) -> None:
        self._url_save.setVisible(text.strip() != self.settings.public_url)
        self._set_field_error(self._url_edit, self._url_error, None)

    def _save_url(self) -> None:
        if self.settings.is_quick_tunnel:
            return
        text = self._url_edit.text().strip()
        if text == self.settings.public_url:
            self._url_save.hide()
            return
        if self.manager.is_active and not self._confirm(
            "Применить новый адрес?",
            "Сервисы перезапустятся с новым адресом.",
        ):
            return
        error = self.manager.set_public_url(text)
        if error:
            self._set_field_error(self._url_edit, self._url_error, error)
            return
        self._url_save.hide()
        self._url_edit.setText(self.settings.public_url)  # нормализованный вид
        self._flash(self._url_copy, "✓ Сохранено")

    # ================================================================== токен
    def _load_token_into_field(self) -> None:
        self._token_edit.setText(self.manager.token)
        self._token_save.hide()
        self._set_field_error(self._token_edit, self._token_error, None)

    def _set_token_visible(self, visible: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        self._token_edit.setEchoMode(mode)
        self._token_eye.setText("Скрыть" if visible else "Показать")

    def _on_token_edited(self, text: str) -> None:
        token = text.strip()
        changed = token != self.manager.token
        self._token_save.setVisible(changed)
        problem = None
        if changed:
            problem = token_store.problem(token) if token else "Токен не может быть пустым."
        self._set_field_error(self._token_edit, self._token_error, problem)
        self._token_save.setEnabled(problem is None)

    def _save_token(self) -> None:
        token = self._token_edit.text().strip()
        if token == self.manager.token:
            self._token_save.hide()
            return
        problem = token_store.problem(token) if token else "Токен не может быть пустым."
        if problem:
            self._set_field_error(self._token_edit, self._token_error, problem)
            return
        if not self._confirm("Сменить токен?", self._token_warning()):
            return
        error = self.manager.set_token(token)
        if error:
            self._set_field_error(self._token_edit, self._token_error, error)

    def _generate_token(self) -> None:
        if not self._confirm("Сгенерировать новый токен?", self._token_warning()):
            return
        error = self.manager.generate_token()
        if error:
            self._set_field_error(self._token_edit, self._token_error, error)
            return
        self._set_token_visible(True)  # сразу показать, чтобы было что скопировать

    def _token_warning(self) -> str:
        text = "Старый токен перестанет работать: обновите его в Notion, ChatGPT и других клиентах."
        if self.manager.is_active:
            text += "\n\nСервисы перезапустятся."
        return text

    def _on_token_changed(self) -> None:
        self._load_token_into_field()
        self._refresh_copy_buttons()

    def _on_query_toggled(self, enabled: bool) -> None:
        self.manager.set_allow_query_token(enabled)
        self._refresh_copy_buttons()

    def _redact(self, line: str) -> str:
        """Токен не попадает в журнал ни целиком, ни в составе ссылки."""
        token = self.manager.token
        if token and token in line:
            line = line.replace(token, token_store.mask(token))
        return _QUERY_TOKEN_RE.sub(r"\1•••", line) if "token=" in line else line

    # ================================================================== параметры
    def _on_autostart(self, enabled: bool) -> None:
        try:
            autostart.set_enabled(enabled)
        except OSError as exc:
            self.manager.log_line.emit(APP, f"✖ Не удалось изменить автозапуск: {exc}")
            self._autostart.blockSignals(True)
            self._autostart.setChecked(not enabled)
            self._autostart.blockSignals(False)
            return
        if enabled and not self._start_on_launch.isChecked():
            # Без этого автозапуск просто открыл бы трей с остановленными сервисами.
            self._start_on_launch.setChecked(True)

    def _on_start_on_launch(self, enabled: bool) -> None:
        self.settings.start_services_on_launch = enabled
        self._save_settings()

    def _on_minimize_toggled(self, enabled: bool) -> None:
        self.settings.minimize_to_tray_on_close = enabled
        self._save_settings()

    # ================================================================== журнал
    def _set_logs_expanded(self, expanded: bool, animate: bool = True) -> None:
        if self.settings.logs_expanded != expanded:
            self.settings.logs_expanded = expanded
            self._save_settings()
        self._logs_toggle.setText(("▾  " if expanded else "▸  ") + "Журнал")
        self._logs_copy.setVisible(expanded)
        self._logs_clear.setVisible(expanded)
        # Развёрнутый журнал забирает свободное место, свёрнутый — отдаёт его распорке.
        self._layout.setStretch(self._logs_index, 1 if expanded else 0)
        self._layout.setStretch(self._spacer_index, 0 if expanded else 1)
        if expanded:
            self._unseen_errors = 0
            self._update_badge()
        if animate:
            effects.reveal(self._log_view, expanded, LOG_HEIGHT)
        else:
            self._log_view.setVisible(expanded)

    def _on_error_logged(self) -> None:
        if not self.settings.logs_expanded:
            self._unseen_errors += 1
            self._update_badge()

    def _update_badge(self) -> None:
        count = self._unseen_errors
        self._error_badge.setVisible(count > 0)
        if count:
            self._error_badge.setText(f"{count if count < 100 else '99+'} ошиб.")

    # ================================================================== утилиты
    def _refresh_copy_buttons(self) -> None:
        url = self.manager.public_url
        self._url_copy.setEnabled(bool(url))
        allowed = self.settings.allow_query_token
        self._copy_full.setVisible(allowed)
        self._copy_full.setEnabled(allowed and bool(url) and bool(self.manager.token))

    def _copy(self, text: str, button: QPushButton) -> None:
        if not text:
            return
        QGuiApplication.clipboard().setText(text)
        self._flash(button, "✓ Скопировано")

    @staticmethod
    def _flash(button: QPushButton, text: str) -> None:
        """Временно сменить подпись кнопки — подтверждение действия без всплывающих окон."""
        original = button.property("flash_original")
        if original is None:
            original = button.text()
            button.setProperty("flash_original", original)
        button.setText(text)
        generation = (button.property("flash_generation") or 0) + 1
        button.setProperty("flash_generation", generation)

        def restore() -> None:
            if button.property("flash_generation") == generation:
                button.setText(original)
                button.setProperty("flash_original", None)

        QTimer.singleShot(FLASH_MS, restore)

    @staticmethod
    def _set_field_error(edit: QLineEdit, label: QLabel, message: str | None) -> None:
        label.setText(message or "")
        label.setVisible(bool(message))
        if bool(edit.property("invalid")) != bool(message):
            edit.setProperty("invalid", bool(message))
            _repolish(edit)

    def _confirm(self, title: str, text: str) -> bool:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle(APP_NAME)
        box.setText(title)
        box.setInformativeText(text)
        accept = box.addButton("Продолжить", QMessageBox.ButtonRole.AcceptRole)
        cancel = box.addButton("Отмена", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(cancel)
        box.exec()
        return box.clickedButton() is accept

    def _save_settings(self) -> None:
        try:
            self.settings.save()
        except OSError as exc:
            self.manager.log_line.emit(APP, f"✖ Не удалось сохранить настройки: {exc}")

    def _apply_dark_titlebar(self) -> None:
        """Тёмный заголовок окна на Windows 10 (1809+) и 11 — иначе он остаётся белым."""
        if sys.platform != "win32":
            return
        try:
            import ctypes

            hwnd = int(self.winId())
            value = ctypes.c_int(1)
            for attribute in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (новое и старое значение)
                result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)
                )
                if result == 0:
                    break
        except (AttributeError, OSError):
            pass

    # ================================================================== окно / трей
    def show_and_raise(self) -> None:
        if self.isMinimized():
            self.showNormal()
        self.show()
        self.raise_()
        self.activateWindow()

    def allow_close(self) -> None:
        """Вызывается при выходе из приложения: дальше окно закрывается по-настоящему."""
        self._allow_close = True

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self._allow_close:
            event.accept()
            return
        event.ignore()
        if self._tray_available and self.settings.minimize_to_tray_on_close:
            self.hide()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self.hidden_to_tray.emit()
        else:
            self.quit_requested.emit()  # без трея закрытие окна = выход
