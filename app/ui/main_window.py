"""Главное окно MCP app в стиле Claude Desktop.

    ┌ Сайдбар ─────────┬ Холст ────────────────────────────────────────┐
    │ ◆ MCP app        │      Сервер в сети          (антиква)  │
    │ Обзор            │      Клиенты подключаются…             │
    │ Подключение      │  ┌ поднятая карточка ───────────────┐  │
    │ Журнал        3  │  │ Старт/Стоп · сервер · туннель     │  │
    │ Параметры        │  └───────────────────────────────────┘  │
    │                  │  ┌ адрес для клиентов ──────────────┐  │
    │ ● В сети          │  └───────────────────────────────────┘  │
    │ v0.4.0           │                                          │
    └──────────────────┴──────────────────────────────────────────┘

Окно только показывает состояние и передаёт команды. Проверка и применение
настроек (в том числе перезапуск сервисов) — в ServiceManager.
"""
from __future__ import annotations

import re
import sys
from urllib.parse import urlsplit

from PyQt6.QtCore import Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QCloseEvent, QDesktopServices, QGuiApplication, QKeySequence, QShortcut
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
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app import APP_NAME, __version__
from app.config import TUNNEL_NAMED, TUNNEL_QUICK, Settings
from app.core import autostart, token_store
from app.core.process import ProcState
from app.core.service_manager import APP, Overall, ServiceManager
from app.paths import user_data_dir
from app.ui import effects, icons, theme
from app.ui.domain_guide import DomainGuideDialog
from app.ui.widgets import LogView, NavButton, StatusDot, StatusRow

FLASH_MS = 1500
CONTENT_WIDTH = 720  # колонка контента по центру холста, как лента чата в Claude
SIDEBAR_WIDTH = 216
# Значение токена в ссылке: только символы токена, минимум 8 — служебный текст
# вроде «(?token=): разрешён» не задевает.
_QUERY_TOKEN_RE = re.compile(r"(token=)[A-Za-z0-9\-._~+/=]{8,}")

PAGE_OVERVIEW, PAGE_CONNECTION, PAGE_LOGS, PAGE_SETTINGS = range(4)

OVERVIEW_TEXT = {
    "stopped": ("Готов к запуску", "Сервер и туннель остановлены. Нажмите «Запустить», чтобы открыть доступ из интернета."),
    "starting": ("Запускаю…", "Поднимаю MCP-сервер и туннель Cloudflare."),
    "running": ("Сервер в сети", "Клиенты подключаются по адресу ниже."),
    "degraded": ("Переподключаюсь…", "Связь потеряна — перезапускаю то, что упало."),
    "stopping": ("Останавливаю…", "Закрываю туннель, затем сервер."),
    "error": ("Не удалось запустить", "Причина и что с ней делать — в журнале."),
}

NAMED_HINT = (
    "Постоянный адрес на вашем домене через именованный туннель Cloudflare (config.yml). "
    "Адрес ниже должен совпадать с hostname в ingress config.yml."
)
QUICK_HINT = (
    "Не нужны домен и аккаунт Cloudflare. Адрес *.trycloudflare.com выдаётся заново при каждом "
    "запуске — обновляйте его в клиентах. Режим для пробы и тестов: без гарантий доступности, "
    "с лимитом одновременных запросов и без SSE."
)
NO_DOMAIN_HINT = (
    "Свой домен ещё не настроен — сейчас работает временный адрес. Чтобы адрес не менялся, "
    "подключите свой домен по инструкции."
)
TOKEN_HINT = "Клиенты передают его в заголовке Authorization: Bearer <токен>. Хранится только на этом компьютере."
CLIENT_HINT = (
    "В клиенте (Claude, ChatGPT, Notion и др.) добавьте MCP-сервер, он же «коннектор». "
    "Поле для OpenAI-совместимого API не подойдёт: такие клиенты запрашивают /v1/models и получают 404."
)


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


def _card(name: str = "Card", margins: tuple[int, int, int, int] = (20, 18, 20, 20)) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName(name)
    box = QVBoxLayout(frame)
    box.setContentsMargins(*margins)
    box.setSpacing(10)
    return frame, box


def _divider() -> QFrame:
    line = QFrame()
    line.setObjectName("Divider")
    return line


def _page(title: str, lead: str = "", scroll: bool = True) -> tuple[QWidget, QVBoxLayout, QLabel, QLabel]:
    """Страница: колонка CONTENT_WIDTH по центру, заголовок антиквой и подзаголовок."""
    column = QWidget()
    column.setMaximumWidth(CONTENT_WIDTH)
    layout = QVBoxLayout(column)
    layout.setContentsMargins(0, 40, 0, 32)
    layout.setSpacing(16)
    title_label = _label(title, "PageTitle", wrap=True)
    lead_label = _label(lead, "PageLead", wrap=True)
    layout.addWidget(title_label)
    layout.addWidget(lead_label)
    layout.addSpacing(8)

    canvas = QWidget()
    canvas.setObjectName("Canvas")
    row = QHBoxLayout(canvas)
    row.setContentsMargins(40, 0, 40, 0)
    row.addStretch(1)
    row.addWidget(column, 100)
    row.addStretch(1)

    if not scroll:
        return canvas, layout, title_label, lead_label
    area = QScrollArea()
    area.setObjectName("Page")
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setWidget(canvas)
    return area, layout, title_label, lead_label


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
        self._domain_guide: DomainGuideDialog | None = None

        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(icons.app_icon())
        self.setMinimumSize(860, 600)
        self.resize(1040, 760)

        root = QWidget()
        root.setObjectName("Canvas")
        row = QHBoxLayout(root)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)
        row.addWidget(self._build_sidebar())

        self._stack = QStackedWidget()
        self._stack.addWidget(self._build_overview())
        self._stack.addWidget(self._build_connection())
        self._stack.addWidget(self._build_logs())
        self._stack.addWidget(self._build_settings())
        row.addWidget(self._stack, 1)
        self.setCentralWidget(root)

        manager.overall_state_changed.connect(self._on_overall)
        manager.service_state_changed.connect(lambda *_: self._refresh_services())
        manager.log_line.connect(self._log_view.append_line)
        manager.public_url_changed.connect(self._on_public_url)
        manager.token_changed.connect(self._on_token_changed)
        manager.settings_changed.connect(self._refresh_mode)
        self._log_view.set_redactor(self._redact)
        self._log_view.error_logged.connect(self._on_error_logged)

        QShortcut(QKeySequence("Ctrl+Q"), self, activated=self.quit_requested.emit)
        for index in range(4):
            QShortcut(QKeySequence(f"Ctrl+{index + 1}"), self, activated=lambda i=index: self.show_page(i))

        self._refresh_mode()
        self._load_token_into_field()
        self._on_overall(manager.overall)
        self.show_page(PAGE_OVERVIEW)
        self._style_titlebar()

    # ================================================================== сайдбар
    def _build_sidebar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("Sidebar")
        bar.setFixedWidth(SIDEBAR_WIDTH)
        column = QVBoxLayout(bar)
        column.setContentsMargins(12, 18, 12, 14)
        column.setSpacing(2)

        brand = QHBoxLayout()
        brand.setContentsMargins(8, 0, 0, 0)
        brand.setSpacing(10)
        logo = QLabel()
        logo.setPixmap(icons.app_icon().pixmap(26, 26))
        brand.addWidget(logo)
        brand.addWidget(_label(APP_NAME, "Wordmark"))
        brand.addStretch(1)
        column.addLayout(brand)
        column.addSpacing(22)

        self._nav: list[NavButton] = []
        for index, text in enumerate(("Обзор", "Подключение", "Журнал", "Параметры")):
            button = NavButton(text)
            button.setToolTip(f"Ctrl+{index + 1}")
            button.clicked.connect(lambda _c=False, i=index: self.show_page(i))
            column.addWidget(button)
            self._nav.append(button)

        column.addStretch(1)

        chip = QFrame()
        chip.setObjectName("StatusChip")
        chip_row = QHBoxLayout(chip)
        chip_row.setContentsMargins(6, 8, 10, 8)
        chip_row.setSpacing(4)
        self._chip_dot = StatusDot()
        chip_row.addWidget(self._chip_dot, 0, Qt.AlignmentFlag.AlignTop)
        chip_texts = QVBoxLayout()
        chip_texts.setSpacing(1)
        self._chip_text = effects.ShinyLabel("")
        self._chip_text.setObjectName("ChipText")
        self._chip_detail = _label("", "ChipDetail")
        chip_texts.addWidget(self._chip_text)
        chip_texts.addWidget(self._chip_detail)
        chip_row.addLayout(chip_texts, 1)
        column.addWidget(chip)
        column.addSpacing(10)
        column.addWidget(_label(f"Версия {__version__}", "Version"))
        return bar

    def show_page(self, index: int) -> None:
        self._stack.setCurrentIndex(index)
        self._nav[index].setChecked(True)
        if index == PAGE_LOGS:
            self._unseen_errors = 0
            self._nav[PAGE_LOGS].set_badge(0)

    # ================================================================== Обзор
    def _build_overview(self) -> QWidget:
        page, layout, self._ov_title, self._ov_lead = _page("", "")

        hero = effects.SpotlightFrame("Elevated", corner_radius=16)
        box = QVBoxLayout(hero)
        box.setContentsMargins(22, 20, 22, 18)
        box.setSpacing(14)
        top = QHBoxLayout()
        top.setSpacing(16)
        texts = QVBoxLayout()
        texts.setSpacing(4)
        texts.addWidget(_label("Сервисы", "SectionTitle"))
        self._mode_caption = _label("", "Hint", wrap=True)
        texts.addWidget(self._mode_caption)
        top.addLayout(texts, 1)
        self._toggle = effects.SparkButton("Запустить")
        self._toggle.setObjectName("Primary")
        self._toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self._toggle.setMinimumWidth(168)
        self._toggle.clicked.connect(self.manager.toggle)
        top.addWidget(self._toggle, 0, Qt.AlignmentFlag.AlignVCenter)
        box.addLayout(top)
        box.addWidget(_divider())
        self._server_row = StatusRow("MCP-сервер")
        self._tunnel_row = StatusRow("Cloudflare Tunnel")
        box.addWidget(self._server_row)
        box.addWidget(self._tunnel_row)
        layout.addWidget(hero)

        self._error_box = QWidget()
        error_row = QHBoxLayout(self._error_box)
        error_row.setContentsMargins(4, 0, 0, 0)
        error_row.addWidget(_label("Сервисы остановлены из-за ошибки.", "Error"))
        open_log = _button("Открыть журнал →", "Link")
        open_log.clicked.connect(lambda: self.show_page(PAGE_LOGS))
        error_row.addWidget(open_log)
        self._error_guide = _button("Как подключить свой домен", "Link")
        self._error_guide.clicked.connect(self.show_domain_guide)
        error_row.addWidget(self._error_guide)
        error_row.addStretch(1)
        self._error_box.hide()
        layout.addWidget(self._error_box)

        card, cbox = _card()
        cbox.addWidget(_label("Адрес для клиентов", "FieldLabel"))
        self._ov_url = _label("", "Mono", wrap=True)
        self._ov_url.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        cbox.addWidget(self._ov_url)
        actions = QHBoxLayout()
        actions.setSpacing(8)
        self._ov_copy = _button("Копировать адрес")
        self._ov_copy.clicked.connect(lambda: self._copy(self.manager.public_url, self._ov_copy))
        self._ov_copy_token = _button("Копировать токен")
        self._ov_copy_token.clicked.connect(lambda: self._copy(self.manager.token, self._ov_copy_token))
        self._ov_copy_full = _button("Ссылка с токеном", "Ghost", "Адрес с ?token=… — для клиентов без заголовков")
        self._ov_copy_full.clicked.connect(lambda: self._copy(self.manager.url_with_token(), self._ov_copy_full))
        actions.addWidget(self._ov_copy)
        actions.addWidget(self._ov_copy_token)
        actions.addWidget(self._ov_copy_full)
        actions.addStretch(1)
        edit = _button("Изменить", "Link")
        edit.clicked.connect(lambda: self.show_page(PAGE_CONNECTION))
        actions.addWidget(edit)
        cbox.addLayout(actions)
        cbox.addSpacing(2)
        cbox.addWidget(_label(CLIENT_HINT, "Hint", wrap=True))
        layout.addWidget(card)
        layout.addStretch(1)
        return page

    # ================================================================== Подключение
    def _build_connection(self) -> QWidget:
        page, layout, _t, _l = _page("Подключение", "Как сервер виден из интернета и чем защищён.")

        # --- режим и адрес
        card, box = _card()
        head = QHBoxLayout()
        head.addWidget(_label("Публичный адрес", "SectionTitle"))
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
            (TUNNEL_QUICK, "Временный адрес", "Без домена и аккаунта: случайный адрес *.trycloudflare.com"),
            (TUNNEL_NAMED, "Свой домен", "Постоянный адрес через именованный туннель (config.yml)"),
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
        guide_row = QHBoxLayout()
        guide_row.setContentsMargins(0, 0, 0, 0)
        self._guide_link = _button("Как подключить свой домен →", "Link",
                                   "Пошаговая инструкция: аккаунт Cloudflare, туннель, DNS и config.yml")
        self._guide_link.clicked.connect(self.show_domain_guide)
        guide_row.addWidget(self._guide_link)
        guide_row.addStretch(1)
        box.addLayout(guide_row)
        box.addSpacing(4)

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
        layout.addWidget(card)

        # --- токен
        card, box = _card()
        box.addWidget(_label("Токен доступа", "SectionTitle"))
        box.addWidget(_label(TOKEN_HINT, "Hint", wrap=True))
        box.addSpacing(4)
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
        for widget in (self._token_edit, self._token_eye, self._token_save, self._token_copy, self._token_gen):
            token_row.addWidget(widget, 1 if widget is self._token_edit else 0)
        box.addLayout(token_row)
        self._token_error = _label("", "Error", wrap=True)
        self._token_error.hide()
        box.addWidget(self._token_error)
        box.addSpacing(4)
        box.addWidget(_divider())
        query_row = QHBoxLayout()
        self._query_check = QCheckBox("Разрешить токен в ссылке (?token=…)")
        self._query_check.setCursor(Qt.CursorShape.PointingHandCursor)
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
        layout.addWidget(card)
        layout.addStretch(1)
        return page

    # ================================================================== Журнал
    def _build_logs(self) -> QWidget:
        page, layout, _t, _l = _page("Журнал", "Вывод MCP-сервера, cloudflared и самого приложения. Токен вырезается.",
                                     scroll=False)
        actions = QHBoxLayout()
        actions.addStretch(1)
        self._logs_copy = _button("Копировать всё", "Ghost")
        self._logs_clear = _button("Очистить", "Ghost")
        actions.addWidget(self._logs_copy)
        actions.addWidget(self._logs_clear)
        layout.addLayout(actions)
        self._log_view = LogView()
        self._logs_copy.clicked.connect(lambda: self._copy(self._log_view.plain_text(), self._logs_copy))
        self._logs_clear.clicked.connect(self._log_view.clear_log)
        layout.addWidget(self._log_view, 1)
        return page

    # ================================================================== Параметры
    def _build_settings(self) -> QWidget:
        page, layout, _t, _l = _page("Параметры", "Как приложение ведёт себя в Windows.")

        card, box = _card()
        box.setSpacing(4)
        box.addWidget(_label("Запуск", "SectionTitle"))
        box.addSpacing(6)
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
        self._auto_restart = QCheckBox("Перезапускать упавший сервер или туннель")
        self._auto_restart.setChecked(self.settings.auto_restart)
        self._auto_restart.toggled.connect(self._on_auto_restart)
        for check in (self._autostart, self._start_on_launch, self._minimize, self._auto_restart):
            check.setCursor(Qt.CursorShape.PointingHandCursor)
            box.addWidget(check)
        layout.addWidget(card)

        card, box = _card()
        box.addWidget(_label("Компоненты", "SectionTitle"))
        box.addWidget(_label("cloudflared", "FieldLabel"))
        exe = self.manager.cloudflared_path()
        cf = _label(exe or "не найден — установите: winget install --id Cloudflare.cloudflared", "ServiceDetail", wrap=True)
        cf.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        box.addWidget(cf)
        box.addSpacing(6)
        box.addWidget(_label("Данные: настройки, токен, журнал аудита", "FieldLabel"))
        data_row = QHBoxLayout()
        data_dir = user_data_dir()
        data_label = _label(str(data_dir), "ServiceDetail", wrap=True)
        data_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        data_row.addWidget(data_label, 1)
        open_dir = _button("Открыть папку")
        open_dir.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(data_dir))))
        data_row.addWidget(open_dir)
        box.addLayout(data_row)
        layout.addWidget(card)
        layout.addStretch(1)
        return page

    # ================================================================== статусы
    def _on_overall(self, state: Overall) -> None:
        text, color = theme.OVERALL[state.value]
        pending = state.value in theme.PENDING
        self._chip_dot.set_state(color, pending)
        self._chip_text.setText(text)
        self._chip_text.setStyleSheet(f"color: {color};")
        self._chip_text.set_base_color(color)
        self._chip_text.set_shine(pending)

        title, lead = OVERVIEW_TEXT[state.value]
        if state == Overall.STARTING and self.settings.is_quick_tunnel and not self.manager.public_url:
            lead = "Жду временный адрес от Cloudflare — обычно 5–15 секунд."
        if state == Overall.DEGRADED and self.manager.is_diagnosing:
            title, lead = "Проверяю связь…", "Cloudflare не выдал адрес — выясняю, где обрывается связь."
        self._ov_title.setText(title)
        self._ov_lead.setText(lead)
        self._error_box.setVisible(state == Overall.ERROR)

        active = self.manager.is_active
        self._toggle.setText("Остановить" if active else "Запустить")
        self._toggle.setProperty("running", active)
        _repolish(self._toggle)
        self._toggle.setEnabled(active or state != Overall.STOPPING)
        self._refresh_services()

    def _refresh_services(self) -> None:
        m, s = self.manager, self.settings
        quick = s.is_quick_tunnel
        self._apply_row(self._server_row, m.server.state,
                        waiting=m.is_active and quick and m.server.state == ProcState.STOPPED,
                        waiting_text="Ждёт адрес…")
        self._apply_row(self._tunnel_row, m.tunnel.state,
                        waiting=m.is_active and not quick and m.tunnel.state == ProcState.STOPPED,
                        waiting_text="Ждёт сервер…")
        self._server_row.set_detail(f"{s.local_host()}:{s.server_port}")
        host = urlsplit(m.public_url).hostname if m.public_url else ""
        detail = host or ("*.trycloudflare.com" if quick else "—")
        protocol = s.tunnel_protocol.strip()
        self._tunnel_row.set_detail(f"{detail}  ·  {protocol}" if protocol else detail)
        self._chip_detail.setText(host or ("временный адрес" if quick else "свой домен"))
        self._mode_caption.setText(
            "Режим: временный адрес trycloudflare.com" if quick else "Режим: свой домен через config.yml"
        )

    @staticmethod
    def _apply_row(row: StatusRow, state: ProcState, waiting: bool, waiting_text: str) -> None:
        if waiting:
            row.set_state(waiting_text, theme.WARN, pending=True)
            return
        text, color = theme.SERVICE[state.value]
        row.set_state(text, color, pending=state in (ProcState.STARTING, ProcState.STOPPING))

    # ================================================================== режим и адрес
    def show_domain_guide(self) -> None:
        """Немодальное окно с инструкцией: можно копировать команды и параллельно работать в окне."""
        if self._domain_guide is None:
            self._domain_guide = DomainGuideDialog(self.settings, self.manager.cloudflared_path(), self)
        self._domain_guide.show()
        self._domain_guide.raise_()
        self._domain_guide.activateWindow()

    def _on_mode_clicked(self, mode: str) -> None:
        if mode == self.settings.tunnel_mode:
            return
        if mode == TUNNEL_NAMED and not self.settings.has_named_tunnel_config():
            # Своего домена нет: режим не включаем (он всё равно не запустится), а показываем,
            # как его настроить. После шага 5 инструкции кнопка сработает.
            self._refresh_mode()
            self.manager.log_line.emit(
                APP, f"Свой домен ещё не настроен: нет {self.settings.cloudflared_config}. Открыл инструкцию."
            )
            self.show_domain_guide()
            return
        if self.manager.is_active and not self._confirm(
            "Сменить режим туннеля?",
            "Сервисы перезапустятся, а клиентам понадобится новый адрес.",
        ):
            self._refresh_mode()
            return
        self.manager.set_tunnel_mode(mode)  # settings_changed -> _refresh_mode

    def _refresh_mode(self) -> None:
        s = self.settings
        quick = s.is_quick_tunnel
        self._mode_buttons[s.tunnel_mode].setChecked(True)
        if quick:
            hint = QUICK_HINT if s.has_named_tunnel_config() else f"{QUICK_HINT}\n\n{NO_DOMAIN_HINT}"
        else:
            hint = NAMED_HINT
        self._mode_hint.setText(hint)
        self._url_edit.setReadOnly(quick)
        self._url_edit.setPlaceholderText("Появится после запуска туннеля" if quick else "mcp.example.com")
        self._url_edit.setToolTip("" if quick else "Можно ввести только домен — https:// и /mcp добавятся сами")
        self._url_edit.setText(self.manager.public_url)
        self._url_save.hide()
        self._set_field_error(self._url_edit, self._url_error, None)
        self._query_check.blockSignals(True)
        self._query_check.setChecked(s.allow_query_token)
        self._query_check.blockSignals(False)
        self._refresh_address()
        self._refresh_services()

    def _on_public_url(self, url: str) -> None:
        # Не затираем адрес, который пользователь прямо сейчас редактирует.
        if self.settings.is_quick_tunnel or not self._url_save.isVisible():
            self._url_edit.setText(url)
        self._refresh_address()
        self._refresh_services()
        self._on_overall(self.manager.overall)

    def _refresh_address(self) -> None:
        url = self.manager.public_url
        if url:
            self._ov_url.setText(url)
            self._ov_url.setStyleSheet("")
        else:
            if self.settings.is_quick_tunnel:
                placeholder = "Появится после запуска туннеля"
            else:
                placeholder = "Адрес своего домена не указан — «Изменить»"
            self._ov_url.setText(placeholder)
            self._ov_url.setStyleSheet(f"color: {theme.TEXT_FAINT};")
        allowed = self.settings.allow_query_token
        for button in (self._url_copy, self._ov_copy):
            button.setEnabled(bool(url))
        for button in (self._copy_full, self._ov_copy_full):
            button.setVisible(allowed)
            button.setEnabled(allowed and bool(url) and bool(self.manager.token))

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
            "Применить новый адрес?", "Сервисы перезапустятся с новым адресом."
        ):
            return
        error = self.manager.set_public_url(text)
        if error:
            self._set_field_error(self._url_edit, self._url_error, error)
            return
        self._url_save.hide()
        self._url_edit.setText(self.settings.public_url)  # нормализованный вид
        self._refresh_address()
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
        text = "Старый токен перестанет работать: обновите его в Claude, ChatGPT, Notion и других клиентах."
        if self.manager.is_active:
            text += "\n\nСервисы перезапустятся."
        return text

    def _on_token_changed(self) -> None:
        self._load_token_into_field()
        self._refresh_address()

    def _on_query_toggled(self, enabled: bool) -> None:
        self.manager.set_allow_query_token(enabled)
        self._refresh_address()

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

    def _on_auto_restart(self, enabled: bool) -> None:
        self.settings.auto_restart = enabled
        self._save_settings()

    # ================================================================== журнал
    def _on_error_logged(self) -> None:
        if self._stack.currentIndex() != PAGE_LOGS or not self.isVisible():
            self._unseen_errors += 1
            self._nav[PAGE_LOGS].set_badge(self._unseen_errors)

    # ================================================================== утилиты
    def _copy(self, text: str, button: QPushButton) -> None:
        if not text:
            return
        QGuiApplication.clipboard().setText(text)
        self._flash(button, "✓ Скопировано")

    @staticmethod
    def _flash(button: QPushButton, text: str) -> None:
        """Временно сменить подпись кнопки — подтверждение без всплывающих окон."""
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

    def _style_titlebar(self) -> None:
        """Тёмный заголовок окна в цвет холста (Windows 10 1809+ / 11). Ошибки игнорируем."""
        if sys.platform != "win32":
            return
        try:
            import ctypes

            hwnd = int(self.winId())
            dwm = ctypes.windll.dwmapi
            dark = ctypes.c_int(1)
            for attribute in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (новое и старое значение)
                if dwm.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(dark), ctypes.sizeof(dark)) == 0:
                    break
            # Windows 11: цвет заголовка и рамки (COLORREF = 0x00BBGGRR).
            def colorref(hex_color: str) -> ctypes.c_uint:
                r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
                return ctypes.c_uint(b << 16 | g << 8 | r)

            caption, border = colorref(theme.SIDEBAR), colorref(theme.HAIRLINE)
            dwm.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(caption), ctypes.sizeof(caption))  # CAPTION_COLOR
            dwm.DwmSetWindowAttribute(hwnd, 34, ctypes.byref(border), ctypes.sizeof(border))    # BORDER_COLOR
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
