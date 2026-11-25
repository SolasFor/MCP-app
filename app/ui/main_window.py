"""Modular MainWindow in Linear + Docker Desktop style with Dark/Light/System themes and RU/EN i18n."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from PyQt6.QtCore import QEvent, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QCloseEvent, QGuiApplication, QKeySequence, QResizeEvent, QShortcut
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app import APP_NAME
from app.config import (
    ACCESS_PROFILES,
    DEFAULT_ACCESS_PROFILE,
    PROVIDER_CF_NAMED,
    PROVIDER_CF_QUICK,
    PROVIDER_LOCAL,
    PROVIDER_NGROK,
    PROVIDER_NONE,
    PROVIDER_TAILSCALE,
    TUNNEL_NAMED,
    Settings,
)
from app.core import autostart, token_store
from app.core.logging_manager import LogConfig, get_logging_manager
from app.core.process import ProcState
from app.core.service_manager import APP, Overall, ServiceManager
from app.paths import user_data_dir
from app.ui import icons, theme, tokens
from app.ui.components.command_palette import CommandPaletteDialog, PaletteAction
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.sidebar import NavItemSpec, Sidebar
from app.ui.components.silent_dialog import SilentMessageBox
from app.ui.components.toast import ToastManager
from app.ui.connection_diagnostics_dialog import ConnectionDiagnosticsDialog
from app.ui.domain_guide import DomainGuideDialog
from app.ui.domain_wizard import DomainWizard
from app.ui.i18n import LANG_EN, LANG_RU, i18n, tr
from app.ui.oauth_execution_dialogs import ExecutionPolicyDialog
from app.ui.provider_wizards import ProviderConfigDialog
from app.ui.pages import (
    AutomationPage,
    ClientsPage,
    ConnectionsPage,
    DevicesPage,
    ExtensionsPage,
    GatewayPage,
    HomePage,
    LogsPage,
    PlannedPage,
    SecurityPage,
    ServersPage,
    SettingsPage,
    TasksPage,
    WorkspacesPage,
)
from app.ui.widgets import StatusRow, repolish
from backend.oauth_execution import ExecutionApprovals
from backend.oauth_store import OAuthStore, canonical_oauth_urls, default_store_path

_ORIGINAL_DEFAULT_STORE_PATH = default_store_path
FLASH_MS = 1500
_QUERY_TOKEN_RE = re.compile(r"(token=)[A-Za-z0-9\-._~+/=]{8,}")

NAV_SPECS: tuple[NavItemSpec, ...] = (
    NavItemSpec("home", "nav.home", "home", "primary", shortcut="Ctrl+1"),
    NavItemSpec("connections", "nav.connections", "connections", "primary", shortcut="Ctrl+2"),
    NavItemSpec("clients", "nav.clients", "clients", "primary", shortcut="Ctrl+3"),
    NavItemSpec("gateway", "nav.gateway", "gateway", "primary", shortcut="Ctrl+4"),
    NavItemSpec("tasks", "nav.tasks", "tasks", "primary", shortcut="Ctrl+5"),
    NavItemSpec("servers", "nav.servers", "servers", "primary", shortcut="Ctrl+6"),
    NavItemSpec("workspaces", "nav.workspaces", "workspaces", "primary", shortcut="Ctrl+7"),
    NavItemSpec("extensions", "nav.extensions", "extensions", "primary", shortcut=""),
    NavItemSpec("devices", "nav.devices", "devices", "primary", shortcut=""),
    NavItemSpec("security", "nav.security", "security", "primary", shortcut="Ctrl+8"),
    NavItemSpec("logs", "nav.logs", "logs", "primary", shortcut="Ctrl+9"),
    NavItemSpec("settings", "nav.settings", "settings", "primary", shortcut=""),
    NavItemSpec("automation", "nav.automation", "automation", "primary", shortcut=""),
)

PAGE_IDS: tuple[str, ...] = tuple(spec.page_id for spec in NAV_SPECS)
ACTIVE_PAGE_IDS: tuple[str, ...] = tuple(spec.page_id for spec in NAV_SPECS if spec.section == "primary")
PLANNED_PAGE_IDS: tuple[str, ...] = tuple(spec.page_id for spec in NAV_SPECS if spec.section == "upcoming")
NAV_TITLES: tuple[str, ...] = tuple(tr(spec.i18n_key) for spec in NAV_SPECS if spec.section == "primary")

PAGE_OVERVIEW = 0
PAGE_CONNECTION = PAGE_OVERVIEW
PAGE_CONNECTIONS = PAGE_IDS.index("connections")
PAGE_CLIENTS = PAGE_IDS.index("clients")
PAGE_GATEWAY = PAGE_IDS.index("gateway")
PAGE_TASKS = PAGE_IDS.index("tasks")
PAGE_SERVERS = PAGE_IDS.index("servers")
PAGE_WORKSPACES = PAGE_IDS.index("workspaces")
PAGE_EXTENSIONS = PAGE_IDS.index("extensions")
PAGE_DEVICES = PAGE_IDS.index("devices")
PAGE_SECURITY = PAGE_IDS.index("security")
PAGE_LOGS = PAGE_IDS.index("logs")
PAGE_SETTINGS = PAGE_IDS.index("settings")
PAGE_AUTOMATION = PAGE_IDS.index("automation")

_PAGE_NAV_KEY = {spec.page_id: spec.i18n_key for spec in NAV_SPECS}


class MainWindow(QMainWindow):
    quit_requested = pyqtSignal()
    task_notification = pyqtSignal(str, str, str)

    def __init__(
        self,
        manager: ServiceManager,
        settings: Settings,
        tray_available: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.manager = manager
        self.settings = settings
        self._tray_available = tray_available
        self._allow_close = False
        self._unseen_errors = 0
        self._domain_guide: DomainGuideDialog | None = None
        self._domain_wizard: DomainWizard | None = None
        self._current_page_id = "home"

        self.setObjectName("MainWindow")
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(icons.app_icon())
        self.setMinimumSize(tokens.WINDOW_MIN_W, tokens.WINDOW_MIN_H)
        self._restore_geometry()

        root = QWidget()
        root.setObjectName("Canvas")
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        self.sidebar = Sidebar(NAV_SPECS)
        self.sidebar.page_selected.connect(self.show_page)
        self.sidebar.palette_requested.connect(self.open_command_palette)
        self.sidebar.collapse_toggled.connect(self._on_sidebar_collapsed)
        shell.addWidget(self.sidebar)

        right_col = QWidget()
        right_col.setObjectName("Canvas")
        right_box = QVBoxLayout(right_col)
        right_box.setContentsMargins(0, 0, 0, 0)
        right_box.setSpacing(0)

        self._topbar = self._build_topbar()
        right_box.addWidget(self._topbar)

        self._stack = QStackedWidget()
        self.home_page = HomePage()
        self.connections_page = ConnectionsPage()
        self.clients_page = ClientsPage(store_path_fn=self._oauth_store_path)
        self.gateway_page = GatewayPage(config_path=manager.gateway_config_path())
        self.tasks_page = TasksPage(
            db_path=manager.tasks_db_path(),
            spool_dir=manager.tasks_spool_dir(),
            artifacts_dir=manager.tasks_artifacts_dir(),
            redactor=manager._redactor,
        )
        self.servers_page = ServersPage(
            config_path=manager.managed_servers_path(),
            tasks_db_path=manager.tasks_db_path(),
            redactor=manager._redactor,
        )
        self.workspaces_page = WorkspacesPage(
            config_path=manager.workspaces_config_path(),
            history_dir=manager.workspaces_history_dir(),
            redactor=manager._redactor,
        )
        self.extensions_page = ExtensionsPage(
            extensions_dir=manager.extensions_dir(),
            redactor=manager._redactor,
        )
        self.devices_page = DevicesPage(
            config_path=manager.devices_config_path(),
            redactor=manager._redactor,
        )
        self.security_page = SecurityPage(desktop_policy_path=manager.desktop_policy_path())
        self.logs_page = LogsPage()
        self.settings_page = SettingsPage(settings, manager.cloudflared_path(), tray_available)
        self.automation_page = AutomationPage(
            automation_dir=manager.automation_dir(),
            config_root=user_data_dir(),
            redactor=manager._redactor,
        )

        self._pages_by_id: dict[str, QWidget] = {
            "home": self.home_page,
            "connections": self.connections_page,
            "clients": self.clients_page,
            "gateway": self.gateway_page,
            "tasks": self.tasks_page,
            "servers": self.servers_page,
            "workspaces": self.workspaces_page,
            "extensions": self.extensions_page,
            "devices": self.devices_page,
            "security": self.security_page,
            "logs": self.logs_page,
            "settings": self.settings_page,
            "automation": self.automation_page,
        }
        self._planned_pages: dict[str, PlannedPage] = {}
        for spec in NAV_SPECS:
            if spec.section == "upcoming":
                planned = PlannedPage(spec.page_id, f"v{spec.tag}", spec.icon)
                planned.back_home_requested.connect(lambda: self.show_page("home"))
                self._pages_by_id[spec.page_id] = planned
                self._planned_pages[spec.page_id] = planned

        for pid in PAGE_IDS:
            self._stack.addWidget(self._pages_by_id[pid])

        right_box.addWidget(self._stack, 1)
        shell.addWidget(right_col, 1)
        self.setCentralWidget(root)

        self.toasts = ToastManager(self)

        # Backwards-compatible aliases expected by existing tests and callers
        self._toggle = self.home_page.toggle_btn
        self._emergency_btn = self.home_page.emergency_btn
        self._mode_buttons: dict[str, QPushButton] = {}
        self._url_copy = self.home_page.url_copy
        self._access_profile = self.security_page.access_profile
        self._log_view = self.logs_page.viewer.log_view
        self._proxy_page = self.connections_page.proxy_page

        self._connect_page_signals()
        self._connect_manager_signals()
        self._install_shortcuts()

        self._desktop_poll = QTimer(self)
        self._desktop_poll.setInterval(1000)
        self._desktop_poll.timeout.connect(self._refresh_desktop_indicator)

        self.sidebar.set_collapsed(settings.sidebar_collapsed, emit=False)
        self._refresh_mode()
        self._refresh_desktop_indicator()
        self._load_token_into_field()
        self._on_overall(manager.overall)
        self.show_page("home")
        self._apply_theme()
        self.sidebar.button("home").setFocus()

        theme.manager().theme_changed.connect(self._on_theme_changed)
        i18n.language_changed.connect(self._on_language_changed)
        self._desktop_poll.start()

    # ================================================================== layout & shell
    def _build_topbar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("TopBar")
        bar.setFixedHeight(36)
        row = QHBoxLayout(bar)
        row.setContentsMargins(20, 4, 20, 0)
        row.setSpacing(8)

        # Kept hidden so page headers never duplicate in the top chrome
        self._topbar_title = QLabel()
        self._topbar_title.setObjectName("TopBarTitle")
        self._topbar_title.hide()

        self._desktop_indicator_btn = QPushButton("")
        self._desktop_indicator_btn.setObjectName("Danger")
        self._desktop_indicator_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._desktop_indicator_btn.clicked.connect(lambda: self.show_page("security"))
        self._desktop_indicator_btn.hide()
        row.addWidget(self._desktop_indicator_btn)
        row.addStretch(1)

        self._palette_top_btn = QPushButton("")
        self._palette_top_btn.setObjectName("IconBtn")
        self._palette_top_btn.setFixedSize(28, 28)
        self._palette_top_btn.setIconSize(QSize(14, 14))
        self._palette_top_btn.setToolTip(tr("topbar.palette"))
        self._palette_top_btn.setAccessibleName(tr("topbar.palette"))
        self._palette_top_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._palette_top_btn.clicked.connect(self.open_command_palette)
        row.addWidget(self._palette_top_btn)

        self._theme_combo = SafeComboBox()
        self._theme_combo.setObjectName("ThemeCombo")
        self._theme_combo.setMinimumWidth(116)
        self._theme_combo.setIconSize(QSize(13, 13))
        self._theme_combo.setCursor(Qt.CursorShape.PointingHandCursor)
        self._theme_combo.addItem("", theme.THEME_LIGHT)
        self._theme_combo.addItem("", theme.THEME_DARK)
        self._theme_combo.addItem("", theme.THEME_SYSTEM)
        self._theme_combo.currentIndexChanged.connect(self._on_theme_combo_changed)
        row.addWidget(self._theme_combo)
        return bar

    def _connect_page_signals(self) -> None:
        h = self.home_page
        h.toggle_requested.connect(self.manager.toggle)
        h.emergency_stop_requested.connect(self._on_emergency_stop)
        h.open_page_requested.connect(self.show_page)
        h.domain_wizard_requested.connect(self.show_domain_wizard)
        h.connection_diagnostics_requested.connect(self._open_connection_diagnostics)
        h.copy_requested.connect(self._handle_copy_request)

        c = self.connections_page
        c.domain_wizard_requested.connect(self.show_domain_wizard)
        c.domain_guide_requested.connect(self.show_domain_guide)
        c.provider_selected.connect(self._on_provider_selected)
        c.provider_configure_requested.connect(self._open_provider_config)
        c.provider_diagnose_requested.connect(self._open_provider_diagnose)
        c.token_edited.connect(self._on_token_edited)
        c.token_save_requested.connect(self._save_token)
        c.token_generate_requested.connect(self._generate_token)
        c.copy_requested.connect(self._handle_copy_request)
        c.purge_openai_secret_requested.connect(self._on_purge_legacy_openai_secret)
        c.proxy_page.saved.connect(self._on_proxy_saved)

        cl = self.clients_page
        cl.allowlist_requested.connect(self._open_allowlist)
        cl.status_message.connect(self.toasts.show_toast)

        gw = self.gateway_page
        gw.config_changed.connect(self.manager.refresh_gateway_secrets)
        gw.status_message.connect(self.toasts.show_toast)

        tsk = self.tasks_page
        tsk.status_message.connect(self.toasts.show_toast)
        tsk.task_finished.connect(self.task_notification.emit)

        srv = self.servers_page
        srv.config_changed.connect(self.manager.refresh_server_secrets)
        srv.status_message.connect(self.toasts.show_toast)

        ws = self.workspaces_page
        ws.config_changed.connect(self.manager.refresh_workspace_secrets)
        ws.status_message.connect(self.toasts.show_toast)

        self.automation_page.status_message.connect(self.toasts.show_toast)

        s = self.security_page
        s.access_profile_changed.connect(self._on_access_profile_changed)
        s.allowlist_requested.connect(self._open_allowlist)
        s.clients_requested.connect(lambda: self.show_page("clients"))
        s.desktop_policy_changed.connect(self._on_desktop_policy_changed)

        self.logs_page.viewer.copy_requested.connect(self._copy)
        self.logs_page.viewer.exported.connect(lambda msg: self.toasts.show_toast(msg, "ok"))

        st = self.settings_page
        st.theme_mode_selected.connect(self.set_theme_mode)
        st.language_selected.connect(self.set_language)
        st.sidebar_compact_toggled.connect(lambda checked: self.sidebar.set_collapsed(checked, emit=True))
        st.autostart_toggled.connect(self._on_autostart)
        st.start_on_launch_toggled.connect(self._on_start_on_launch)
        st.minimize_toggled.connect(self._on_minimize_toggled)
        st.auto_restart_toggled.connect(self._on_auto_restart)
        st.logging_settings_changed.connect(self._on_logging_settings_changed)

    def _connect_manager_signals(self) -> None:
        m = self.manager
        m.overall_state_changed.connect(self._on_overall)
        m.service_state_changed.connect(lambda *_: self._refresh_services())
        m.log_line.connect(self._log_view.append_line)
        m.public_url_changed.connect(self._on_public_url)
        m.token_changed.connect(self._on_token_changed)
        m.settings_changed.connect(self._refresh_mode)
        self._log_view.set_redactor(self._redact)
        self._log_view.error_logged.connect(self._on_error_logged)

    def _install_shortcuts(self) -> None:
        QShortcut(QKeySequence("Ctrl+Q"), self, activated=self.quit_requested.emit)
        QShortcut(QKeySequence("Ctrl+K"), self, activated=self.open_command_palette)
        QShortcut(
            QKeySequence("Ctrl+B"),
            self,
            activated=lambda: self.sidebar.set_collapsed(not self.sidebar.is_collapsed, emit=True),
        )
        for spec in NAV_SPECS:
            if spec.section == "primary" and spec.shortcut:
                QShortcut(
                    QKeySequence(spec.shortcut),
                    self,
                    activated=lambda p=spec.page_id: self.show_page(p),
                )

    # ================================================================== navigation & palette
    def show_page(self, target: int | str) -> None:
        if isinstance(target, int):
            page_id = PAGE_IDS[target] if 0 <= target < len(PAGE_IDS) else "home"
        else:
            page_id = target if target in self._pages_by_id else "home"
        index = PAGE_IDS.index(page_id)
        self._current_page_id = page_id
        self._ensure_page_themed(page_id)
        self._stack.setCurrentIndex(index)
        self.sidebar.set_current(page_id)
        self._topbar_title.setText(tr(_PAGE_NAV_KEY[page_id]))
        if page_id == "logs":
            self._unseen_errors = 0
            self.sidebar.set_badge("logs", 0)
            self.logs_page.viewer.reload_from_disk()
        elif page_id == "connections":
            self._refresh_services()
        elif page_id == "clients":
            self.clients_page.set_public_url(self._effective_oauth_url())
        elif page_id == "gateway":
            self.gateway_page.reload()
        elif page_id == "tasks":
            self.tasks_page.reload()
        elif page_id == "servers":
            self.servers_page.reload()
        elif page_id == "workspaces":
            self.workspaces_page.reload()
        elif page_id == "automation":
            self.automation_page.reload()

    def _ensure_page_themed(self, page_id: str) -> None:
        page = self._pages_by_id.get(page_id)
        if page is None:
            return
        if theme.manager().apply_to_widget(page) and hasattr(page, "apply_theme"):
            page.apply_theme()  # type: ignore[attr-defined]

    def open_command_palette(self) -> None:
        actions: list[PaletteAction] = []
        nav_cat = tr("nav.section.primary")
        for spec in NAV_SPECS:
            actions.append(
                PaletteAction(
                    action_id=f"nav.{spec.page_id}",
                    title=tr(spec.i18n_key),
                    category=nav_cat,
                    shortcut=spec.shortcut,
                    keywords=spec.page_id,
                    callback=lambda pid=spec.page_id: self.show_page(pid),
                )
            )
        actions.extend(
            [
                PaletteAction(
                    "engine.toggle",
                    tr("home.btn.stop" if self.manager.is_active else "home.btn.start"),
                    "Engine",
                    self.manager.toggle,
                    keywords="start stop engine server",
                ),
                PaletteAction(
                    "engine.copy_url",
                    tr("home.url.copy"),
                    "Engine",
                    lambda: self._copy(self.manager.public_url, self.home_page.ov_copy),
                    keywords="url endpoint copy",
                ),
                PaletteAction(
                    "theme.cycle",
                    tr("settings.theme.label"),
                    tr("nav.settings"),
                    self._cycle_theme_mode,
                    keywords="dark light system theme тема",
                ),
                PaletteAction(
                    "lang.toggle",
                    "Switch RU / EN",
                    tr("nav.settings"),
                    lambda: self.set_language(LANG_EN if i18n.language == LANG_RU else LANG_RU),
                    keywords="language russian english язык",
                ),
                PaletteAction(
                    "sidebar.toggle",
                    tr("sidebar.expand" if self.sidebar.is_collapsed else "sidebar.collapse"),
                    "UI",
                    lambda: self.sidebar.set_collapsed(not self.sidebar.is_collapsed, emit=True),
                    shortcut="Ctrl+B",
                    keywords="sidebar collapse",
                ),
            ]
        )
        dlg = CommandPaletteDialog(actions, self)
        dlg.exec()

    # ================================================================== theme & i18n
    def set_theme_mode(self, mode: str) -> None:
        normalized = mode if mode in theme.THEME_MODES else theme.THEME_DARK
        self.settings.theme_mode = normalized
        chosen = theme.manager().set_mode(
            normalized,
            QApplication.instance() if isinstance(QApplication.instance(), QApplication) else None,
        )
        self.settings.theme_mode = chosen
        self._save_settings()
        self._sync_theme_controls()

    def _on_theme_combo_changed(self, _index: int) -> None:
        mode = str(self._theme_combo.currentData() or theme.THEME_DARK)
        if mode != self.settings.theme_mode:
            self.set_theme_mode(mode)

    def _cycle_theme_mode(self) -> None:
        order = (theme.THEME_LIGHT, theme.THEME_DARK, theme.THEME_SYSTEM)
        nxt = order[(order.index(self.settings.theme_mode) + 1) % len(order)] if self.settings.theme_mode in order else theme.THEME_DARK
        self.set_theme_mode(nxt)

    def _sync_theme_controls(self) -> None:
        mode = self.settings.theme_mode if self.settings.theme_mode in theme.THEME_MODES else theme.THEME_DARK
        self.settings_page.sync_selections(
            mode, self.settings.language, self.sidebar.is_collapsed
        )
        self._theme_combo.blockSignals(True)
        for idx, opt_mode in enumerate((theme.THEME_LIGHT, theme.THEME_DARK, theme.THEME_SYSTEM)):
            icon_name = {
                theme.THEME_LIGHT: "sun",
                theme.THEME_DARK: "moon",
                theme.THEME_SYSTEM: "monitor",
            }[opt_mode]
            self._theme_combo.setItemText(idx, tr(f"settings.theme.{opt_mode}"))
            self._theme_combo.setItemIcon(idx, icons.vector_icon(icon_name, theme.TEXT_MUTED, 14))
        target_idx = self._theme_combo.findData(mode)
        if target_idx >= 0:
            self._theme_combo.setCurrentIndex(target_idx)
        self._theme_combo.setToolTip(tr("topbar.theme.tooltip"))
        self._theme_combo.blockSignals(False)

    def set_language(self, lang: str) -> None:
        chosen = i18n.set_language(lang)
        theme.manager().refresh_translations()
        self.settings.language = chosen
        self._save_settings()
        self._sync_theme_controls()
        self.toasts.show_toast(tr("toast.lang_changed"), "info")

    def _on_theme_changed(self, *_args: object) -> None:
        self._apply_theme()

    def _on_language_changed(self, *_args: object) -> None:
        self._retranslate_all()

    def _apply_theme(self) -> None:
        theme.apply_window_titlebar(self)
        tm = theme.manager()
        tm.apply_to_widget(self.sidebar)
        tm.apply_to_widget(self._topbar)
        tm.apply_to_widget(self.toasts._container)
        self.sidebar.apply_theme()
        self._ensure_page_themed(self._current_page_id)
        self._palette_top_btn.setIcon(icons.vector_icon("search", theme.TEXT_MUTED, 13))
        self._sync_theme_controls()
        self._refresh_status_colors()
        if self._domain_guide is not None and self._domain_guide.isVisible():
            tm.apply_to_widget(self._domain_guide)
            self._domain_guide.apply_theme()

    def _refresh_status_colors(self) -> None:
        self._on_overall_visual_sync()

    def _retranslate_all(self) -> None:
        self.sidebar.retranslate()
        self._topbar_title.setText(tr(_PAGE_NAV_KEY[self._current_page_id]))
        self._palette_top_btn.setToolTip(tr("topbar.palette"))
        self._palette_top_btn.setAccessibleName(tr("topbar.palette"))
        self._sync_theme_controls()
        for page in self._pages_by_id.values():
            if hasattr(page, "retranslate"):
                page.retranslate()  # type: ignore[attr-defined]
        self._refresh_mode()
        self._refresh_desktop_indicator()
        self._on_overall(self.manager.overall)

    def _on_sidebar_collapsed(self, collapsed: bool) -> None:
        self.settings.sidebar_collapsed = collapsed
        self._save_settings()
        self.settings_page.sync_selections(self.settings.theme_mode, self.settings.language, collapsed)

    # ================================================================== status & services
    def _on_overall_visual_sync(self) -> None:
        state = self.manager.overall
        sidebar_label = tr(f"sidebar.server.{state.value}")
        _overall_text, color = theme.overall_label_color(state.value)
        pending = state.value in theme.PENDING
        host = urlsplit(self.manager.public_url).hostname if self.manager.public_url else ""
        quick = self.settings.is_quick_tunnel
        detail = host or tr("common.quick_short" if quick else "common.named_short")
        self.sidebar.set_engine_status(sidebar_label, detail, color, pending)
        self._refresh_services(refresh_connections=False)

    def _on_overall(self, state: Overall) -> None:
        self._on_overall_visual_sync()
        self._refresh_connections_panel()
        self.home_page.error_banner.setVisible(state == Overall.ERROR)
        self.home_page.err_domain_btn.setVisible(not self.manager.has_domain())

        active = self.manager.is_active
        self._toggle.setText(tr("home.btn.stop" if active else "home.btn.start"))
        self._toggle.setProperty("running", active)
        repolish(self._toggle)
        self._toggle.setEnabled(active or state != Overall.STOPPING)
        self._emergency_btn.setVisible(active)

    def _refresh_services(self, *, refresh_connections: bool = True) -> None:
        m, s = self.manager, self.settings
        pid = m.active_provider
        quick = m.is_quick

        # 1. MCP Server row
        self._apply_row(
            self.home_page.server_row,
            m.server.state,
            waiting=m.is_active and quick and m.server.state == ProcState.STOPPED,
            waiting_text=tr("status.waiting_url"),
        )

        # 2. Tunnel / active transport row
        tunnel_titles = {
            PROVIDER_CF_QUICK: "Cloudflare Tunnel",
            PROVIDER_CF_NAMED: "Cloudflare Tunnel",
            PROVIDER_NGROK: "ngrok Agent",
            PROVIDER_TAILSCALE: "Tailscale Funnel",
            PROVIDER_LOCAL: "Local Loopback",
            PROVIDER_NONE: tr("conn.provider.none"),
        }
        self.home_page.tunnel_row.set_title(tunnel_titles.get(pid, "Tunnel"))
        if pid in (PROVIDER_LOCAL, PROVIDER_NONE):
            srv_running = m.server.state == ProcState.RUNNING
            tunnel_state_text = tr("status.service.running" if srv_running else "status.service.stopped")
            tunnel_color = theme.OK if srv_running else theme.IDLE
            tunnel_line = tr("home.tunnel.none")
            self.home_page.tunnel_row.set_state(tunnel_state_text, tunnel_color)
        elif pid == PROVIDER_TAILSCALE:
            ts_on = m._tailscale_active
            tunnel_state_text = tr("status.tunnel.connected" if ts_on else "status.service.stopped")
            tunnel_color = theme.OK if ts_on else theme.IDLE
            tunnel_line = tr("home.tunnel.running" if ts_on else "home.tunnel.stopped")
            self.home_page.tunnel_row.set_state(tunnel_state_text, tunnel_color)
        else:
            waiting_srv = m.is_active and not quick and m.tunnel.state == ProcState.STOPPED
            if waiting_srv:
                self.home_page.tunnel_row.set_state(tr("status.waiting_server"), theme.WARN, pending=True)
                tunnel_line = tr("home.tunnel.starting")
            else:
                t_state = m.tunnel.state
                if t_state == ProcState.RUNNING:
                    self.home_page.tunnel_row.set_state(tr("status.tunnel.connected"), theme.OK)
                    tunnel_line = tr("home.tunnel.running")
                elif t_state == ProcState.STARTING:
                    self.home_page.tunnel_row.set_state(tr("status.service.starting"), theme.WARN, pending=True)
                    tunnel_line = tr("home.tunnel.starting")
                elif t_state == ProcState.STOPPING:
                    self.home_page.tunnel_row.set_state(tr("status.service.stopping"), theme.WARN, pending=True)
                    tunnel_line = tr("home.tunnel.stopping")
                elif t_state == ProcState.FAILED:
                    self.home_page.tunnel_row.set_state(tr("status.service.failed"), theme.ERR)
                    tunnel_line = tr("home.tunnel.failed")
                else:
                    self.home_page.tunnel_row.set_state(tr("status.service.stopped"), theme.IDLE)
                    tunnel_line = tr("home.tunnel.stopped")

        # 3. OAuth readiness row (honest state derived from running MCP server + effective OAuth URL)
        oauth_ready = m.server.state == ProcState.RUNNING and bool(self._effective_oauth_url())
        if oauth_ready:
            self.home_page.oauth_row.set_state(tr("home.oauth.ready"), theme.OK)
        elif m.is_active and m.overall in (Overall.STARTING, Overall.DEGRADED):
            self.home_page.oauth_row.set_state(tr("home.oauth.waiting"), theme.WARN, pending=True)
        else:
            self.home_page.oauth_row.set_state(tr("home.oauth.stopped"), theme.IDLE)

        local_addr = f"MCP {s.local_host()}:{s.server_port}"
        self.home_page.server_row.set_detail(f"{s.local_host()}:{s.server_port}")
        host = urlsplit(m.public_url).hostname if m.public_url else ""
        if pid in (PROVIDER_LOCAL, PROVIDER_NONE):
            detail = (
                f"http://{s.local_host()}:{s.server_port}{s.mcp_path} (no tunnel)"
                if pid == PROVIDER_LOCAL
                else tr("conn.provider.none")
            )
        else:
            detail = host or ("*.trycloudflare.com" if quick else "—")
            parts = [detail]
            if pid in (PROVIDER_CF_QUICK, PROVIDER_CF_NAMED) and m.tunnel_protocol:
                parts.append(m.tunnel_protocol)
            if pid in (PROVIDER_CF_QUICK, PROVIDER_CF_NAMED) and m.proxy_enabled:
                parts.append(tr("common.via_proxy"))
            detail = "  ·  ".join(parts)
        self.home_page.tunnel_row.set_detail(detail)

        overall_state = m.overall
        hero_title = tr(f"home.hero.{overall_state.value}")
        _lbl, dot_color = theme.overall_label_color(overall_state.value)
        self.home_page.set_hero_status(
            title=hero_title,
            dot_color=dot_color,
            pending=overall_state.value in theme.PENDING,
            local_addr=local_addr,
            tunnel_line=tunnel_line,
            running=m.is_active,
        )

        if refresh_connections:
            self._refresh_connections_panel()

    def _refresh_connections_panel(self) -> None:
        m, s = self.manager, self.settings
        pid = m.active_provider
        try:
            statuses = m.connections.list_statuses(
                local_host=s.local_host(),
                local_port=s.server_port,
                mcp_path=s.mcp_path,
                runtime_url=m.public_url,
                running=m.overall == Overall.RUNNING,
            )
        except Exception:
            statuses = {}
        self.connections_page.refresh_providers(
            active_provider=pid,
            statuses=statuses,
            has_domain=m.has_domain(),
        )
        migrated_from = str(getattr(m, "migrated_from_provider", "") or getattr(self.settings, "migrated_from_provider", ""))
        self.connections_page.set_legacy_openai_migration(
            migrated=bool(getattr(m, "migrated_from_openai_tunnel", False)) or migrated_from in ("openai_tunnel", "local_only"),
            has_secret=bool(m.has_legacy_openai_secret()) if hasattr(m, "has_legacy_openai_secret") else False,
            migrated_from=migrated_from,
        )

    @staticmethod
    def _apply_row(row: StatusRow, state: ProcState, waiting: bool, waiting_text: str) -> None:
        if waiting:
            row.set_state(waiting_text, theme.WARN, pending=True)
            return
        text, color = theme.service_label_color(state.value)
        row.set_state(text, color, pending=state in (ProcState.STARTING, ProcState.STOPPING))

    # ================================================================== endpoint & modes
    def show_domain_guide(self) -> None:
        if self._domain_guide is None:
            self._domain_guide = DomainGuideDialog(self.settings, self.manager.cloudflared_path(), self)
        else:
            self._domain_guide.apply_theme()
        self._domain_guide.show()
        self._domain_guide.raise_()
        self._domain_guide.activateWindow()

    def show_domain_wizard(self) -> None:
        if self._domain_wizard is None:
            self._domain_wizard = DomainWizard(self.settings.server_port, self)
            self._domain_wizard.guide_requested.connect(self.show_domain_guide)
            self._domain_wizard.configured.connect(self._on_domain_configured)
            self._domain_wizard.finished.connect(self._on_domain_wizard_closed)
        self._domain_wizard.show()
        self._domain_wizard.raise_()
        self._domain_wizard.activateWindow()

    def _on_domain_wizard_closed(self, _result: int) -> None:
        if self._domain_wizard is not None:
            self._domain_wizard.deleteLater()
            self._domain_wizard = None

    def _on_domain_configured(self, state: object) -> None:
        error = self.manager.apply_domain(state)
        if error:
            self.manager.log_line.emit(APP, f"✖ {error}")
        self._refresh_mode()
        self.show_page("home")

    def _on_mode_clicked(self, mode: str) -> None:
        target_provider = PROVIDER_CF_NAMED if mode == TUNNEL_NAMED else PROVIDER_CF_QUICK
        if target_provider == self.manager.active_provider:
            return
        self._on_provider_selected(target_provider)

    def _on_provider_selected(self, provider_id: str) -> None:
        if provider_id == self.manager.active_provider:
            return
        if provider_id == PROVIDER_CF_NAMED and not self.manager.has_domain():
            self._refresh_mode()
            self.manager.log_line.emit(APP, "Свой домен ещё не настроен — открыл мастер настройки.")
            self.show_domain_wizard()
            return
        warning = self.manager.check_issuer_transition(provider_id)
        if warning.issuer_changed:
            msg = tr(
                "conn.issuer_change.body",
                prev=warning.previous_issuer or "—",
                next=warning.next_issuer or "—",
                note=warning.message,
            )
            if not self._confirm(tr("conn.issuer_change.title"), msg):
                self._refresh_mode()
                return
        elif self.manager.is_active and not self._confirm(
            "Сменить транспорт?",
            "Сервисы перезапустятся, а клиентам понадобится новый адрес.",
        ):
            self._refresh_mode()
            return
        self.manager.set_active_provider(provider_id)

    def _open_provider_config(self, provider_id: str) -> None:
        if provider_id == PROVIDER_CF_NAMED:
            self.show_domain_wizard()
            return
        if provider_id == PROVIDER_CF_QUICK:
            self.show_domain_guide()
            return
        dlg = ProviderConfigDialog(
            self.manager.connections,
            provider_id,
            local_host=self.settings.local_host(),
            local_port=self.settings.server_port,
            mcp_path=self.settings.mcp_path,
            parent=self,
        )
        if dlg.exec():
            for secret in self.manager.connections.collect_secret_values():
                self.manager._redactor.register(secret)
            self._refresh_mode()

    def _open_provider_diagnose(self, provider_id: str) -> None:
        checks = self.manager.connections.diagnose_provider(
            provider_id,
            local_host=self.settings.local_host(),
            local_port=self.settings.server_port,
            mcp_path=self.settings.mcp_path,
        )
        lines = [f"{'✓' if c.ok else '✕'} {c.label}: {c.detail}" for c in checks]
        SilentMessageBox.information(self, f"{APP_NAME} — {provider_id}", "\n".join(lines))

    def _on_purge_legacy_openai_secret(self) -> None:
        if not self.manager.has_legacy_openai_secret():
            self.connections_page.set_legacy_openai_migration(
                migrated=self.manager.migrated_from_openai_tunnel,
                has_secret=False,
            )
            return
        if not self._confirm(
            tr("conn.openai_removed.purge_confirm_title"),
            tr("conn.openai_removed.purge_confirm_body"),
        ):
            return
        removed = self.manager.purge_legacy_openai_secret()
        self.connections_page.set_legacy_openai_migration(
            migrated=self.manager.migrated_from_openai_tunnel,
            has_secret=self.manager.has_legacy_openai_secret(),
        )
        self.toasts.show_toast(
            tr("conn.openai_removed.purge_done" if removed else "conn.openai_removed.purge_missing"),
            "ok" if removed else "info",
        )

    def _open_connection_diagnostics(self) -> None:
        url = (
            self.manager.public_url
            or f"http://{self.settings.local_host()}:{self.settings.server_port}{self.settings.mcp_path}"
        )
        recent = tuple(
            line for line in self._log_view.plain_text().splitlines()[-40:] if line.strip()
        )
        dlg = ConnectionDiagnosticsDialog(
            url,
            self.settings.server_port,
            self.settings.server_health_path,
            self.manager.token,
            self,
            tunnel_mode=self.manager.active_provider,
            tunnel_protocol=self.manager.tunnel_protocol,
            recent_logs=recent,
        )
        dlg.exec()

    def _refresh_mode(self) -> None:
        self._refresh_address()
        self._refresh_access_profile()
        self._refresh_services()

    def _on_public_url(self, _url: str) -> None:
        self._refresh_address()
        self._refresh_access_profile()
        self._refresh_services()
        self._on_overall(self.manager.overall)

    def _refresh_address(self) -> None:
        ident = self.manager.connection_identity
        url = self.manager.public_url
        h = self.home_page
        if url:
            h.set_endpoint(url, muted=False)
        elif ident.provider_id == PROVIDER_LOCAL:
            h.set_endpoint(
                ident.local_url,
                display_text=tr("home.url.local_only_value", local_url=ident.local_url),
                muted=False,
            )
        elif ident.provider_id == PROVIDER_NONE:
            h.set_endpoint("", display_text=tr("conn.provider.none"), muted=True)
        else:
            h.set_endpoint(
                "",
                display_text=tr(
                    "home.url.placeholder_quick" if self.settings.is_quick_tunnel else "home.url.placeholder_named"
                ),
                muted=True,
            )

    # ================================================================== OAuth & security
    def _oauth_store_path(self):  # noqa: ANN202
        if default_store_path is not _ORIGINAL_DEFAULT_STORE_PATH:
            return default_store_path()
        path = getattr(self.manager, "oauth_store_path", None)
        if path is not None:
            return path
        return default_store_path()

    def _effective_oauth_url(self) -> str:
        active_url = getattr(self.manager, "active_server_oauth_url", "")
        if isinstance(active_url, str) and active_url:
            return active_url
        if self.manager.public_url:
            return self.manager.public_url
        if self.manager.is_active and self.manager.active_provider == PROVIDER_LOCAL:
            return self.manager.oauth_resource_url
        return ""

    def _execution_store(self) -> ExecutionApprovals | None:
        url = self._effective_oauth_url()
        if not url:
            return None
        parts = urlsplit(url)
        if parts.scheme not in ("https", "http") or not parts.netloc:
            return None
        issuer, resource_url = canonical_oauth_urls(url)
        default_prof = (
            self.settings.default_access_profile
            if self.settings.default_access_profile in ACCESS_PROFILES
            else "safe"
        )
        return ExecutionApprovals(
            OAuthStore(self._oauth_store_path(), issuer, resource_url),
            default_profile=default_prof,
        )

    def _configured_default_profile(self) -> str:
        prof = getattr(self.settings, "default_access_profile", DEFAULT_ACCESS_PROFILE)
        return prof if prof in ACCESS_PROFILES else "safe"

    def _refresh_access_profile(self) -> None:
        try:
            execution = self._execution_store()
            mode = execution.profile() if execution else self._configured_default_profile()
            self._access_profile.setEnabled(True)
            index = self._access_profile.findData(mode)
            self._access_profile.blockSignals(True)
            self._access_profile.setCurrentIndex(max(index, 0))
            self._access_profile.blockSignals(False)
            self.security_page.set_access_mode(mode)
            oauth_url = self._effective_oauth_url()
            self.clients_page.set_public_url(oauth_url if execution else "")
        except Exception as exc:
            self._access_profile.setEnabled(True)
            self._access_profile.blockSignals(True)
            self._access_profile.setCurrentIndex(max(self._access_profile.findData("safe"), 0))
            self._access_profile.blockSignals(False)
            self.security_page.access_profile_hint.setText(f"{type(exc).__name__}")

    def _on_access_profile_changed(self, _index: int) -> None:
        mode = str(self._access_profile.currentData() or "safe")
        try:
            execution = self._execution_store()
            current_mode = execution.profile() if execution is not None else self._configured_default_profile()
            if mode == current_mode:
                return
            if mode == "full":
                answer = SilentMessageBox.warning(
                    self,
                    "Полный доступ без подтверждений",
                    "OAuth-клиенты без индивидуального режима смогут сразу выполнять "
                    "произвольные Windows-команды на этом компьютере и SSH-команды "
                    "на доверенных хостах без подтверждения каждого действия. "
                    "Команды работают с правами текущего пользователя. "
                    "Это высокий риск при доступе через интернет.\n\n"
                    "Включить полный доступ?",
                    SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
                    SilentMessageBox.StandardButton.No,
                )
                if answer != SilentMessageBox.StandardButton.Yes:
                    self._refresh_access_profile()
                    return
            self.settings.default_access_profile = mode if mode in ACCESS_PROFILES else "safe"
            self._save_settings()
            if execution is not None:
                execution.set_profile(mode)
            else:
                ExecutionApprovals.save_default_template(self._oauth_store_path(), profile=mode)
            get_logging_manager().info(
                "oauth",
                f"Default OAuth access profile updated: {current_mode} -> {mode}",
                event_code="oauth_default_profile_changed",
            )
            self._refresh_access_profile()
        except (ValueError, OSError, RuntimeError) as exc:
            SilentMessageBox.warning(
                self, "Режим доступа", f"Не удалось сохранить режим: {type(exc).__name__}"
            )
            self._refresh_access_profile()

    def _open_allowlist(self) -> None:
        try:
            execution = self._execution_store()
            if execution is None:
                execution = ExecutionApprovals.default_template(
                    self._oauth_store_path(),
                    default_profile=self._configured_default_profile(),
                )
            ExecutionPolicyDialog(execution, self).exec()
        except (ValueError, OSError, RuntimeError) as exc:
            SilentMessageBox.warning(self, "Белый список", f"Не удалось открыть: {type(exc).__name__}")

    def _on_emergency_stop(self) -> None:
        report = self.manager.emergency_stop()
        self.security_page.reload_desktop_policy()
        self._refresh_desktop_indicator()
        SilentMessageBox.warning(
            self,
            tr("home.btn.emergency"),
            f"{report['warning']}",
        )

    def _on_desktop_policy_changed(self) -> None:
        self._refresh_desktop_indicator()

    def _refresh_desktop_indicator(self) -> None:
        try:
            pol = self.security_page._desktop_store.load()
            act = self.security_page._desktop_store.read_activity()
            if act.get("active"):
                self._desktop_indicator_btn.setText(tr("topbar.desktop_active"))
                self._desktop_indicator_btn.setObjectName("Danger")
                repolish(self._desktop_indicator_btn)
                self._desktop_indicator_btn.show()
            elif pol.enabled and not pol.emergency_stop and pol.allow_input_control:
                self._desktop_indicator_btn.setText(tr("topbar.desktop_control"))
                self._desktop_indicator_btn.setObjectName("Danger")
                repolish(self._desktop_indicator_btn)
                self._desktop_indicator_btn.show()
            elif pol.enabled and not pol.emergency_stop and pol.allow_screen_capture:
                self._desktop_indicator_btn.setText(tr("topbar.desktop_view"))
                self._desktop_indicator_btn.setObjectName("Secondary")
                repolish(self._desktop_indicator_btn)
                self._desktop_indicator_btn.show()
            else:
                self._desktop_indicator_btn.hide()
        except Exception:
            self._desktop_indicator_btn.hide()

    def _on_proxy_saved(self, settings: object) -> None:
        self.manager.apply_proxy_settings(settings)
        self._refresh_services()

    # ================================================================== token
    def _load_token_into_field(self) -> None:
        c = self.connections_page
        c.token_edit.setText(self.manager.token)
        c.token_save.hide()
        self._set_field_error(c.token_edit, c.token_error, None)

    def _on_token_edited(self, text: str) -> None:
        c = self.connections_page
        token = text.strip()
        changed = token != self.manager.token
        c.token_save.setVisible(changed)
        problem = None
        if changed:
            problem = token_store.problem(token) if token else "Токен не может быть пустым."
        self._set_field_error(c.token_edit, c.token_error, problem)
        c.token_save.setEnabled(problem is None)

    def _save_token(self) -> None:
        c = self.connections_page
        token = c.token_edit.text().strip()
        if token == self.manager.token:
            c.token_save.hide()
            return
        problem = token_store.problem(token) if token else "Токен не может быть пустым."
        if problem:
            self._set_field_error(c.token_edit, c.token_error, problem)
            return
        if not self._confirm("Сменить токен?", self._token_warning()):
            return
        error = self.manager.set_token(token)
        if error:
            self._set_field_error(c.token_edit, c.token_error, error)

    def _generate_token(self) -> None:
        if not self._confirm("Сгенерировать новый токен?", self._token_warning()):
            return
        error = self.manager.generate_token()
        if error:
            self._set_field_error(self.connections_page.token_edit, self.connections_page.token_error, error)
            return
        self.connections_page.set_token_visible(True)

    def _token_warning(self) -> str:
        text = (
            "Старый токен перестанет работать: обновите его в клиентах. "
            "Ранее выданные OAuth-токены будут отозваны, а при переподключении клиенты "
            "должны пройти OAuth-авторизацию заново с новым токеном владельца."
        )
        if self.manager.is_active:
            text += "\n\nПерезапустится только локальный MCP-сервер (активный туннель сохранится)."
        return text

    def _on_token_changed(self) -> None:
        self._load_token_into_field()
        self._refresh_address()

    def _redact(self, line: str) -> str:
        cleaned = self.manager.redact_text(line)
        return _QUERY_TOKEN_RE.sub(r"\1•••", cleaned) if "token=" in cleaned else cleaned

    # ================================================================== settings & logs
    def _on_autostart(self, enabled: bool) -> None:
        try:
            autostart.set_enabled(enabled)
        except OSError as exc:
            self.manager.log_line.emit(APP, f"✖ Не удалось изменить автозапуск: {exc}")
            self.settings_page.autostart.blockSignals(True)
            self.settings_page.autostart.setChecked(not enabled)
            self.settings_page.autostart.blockSignals(False)
            return
        if enabled and not self.settings_page.start_on_launch.isChecked():
            self.settings_page.start_on_launch.setChecked(True)

    def _on_start_on_launch(self, enabled: bool) -> None:
        self.settings.start_services_on_launch = enabled
        self._save_settings()

    def _on_minimize_toggled(self, enabled: bool) -> None:
        self.settings.minimize_to_tray_on_close = enabled
        self._save_settings()

    def _on_auto_restart(self, enabled: bool) -> None:
        self.settings.auto_restart = enabled
        self._save_settings()

    def _on_logging_settings_changed(self, cfg_dict: dict) -> None:
        s = self.settings
        s.logging_enabled = bool(cfg_dict.get("logging_enabled", True))
        s.logging_level = str(cfg_dict.get("logging_level", "INFO")).upper()
        s.logging_max_file_mb = int(cfg_dict.get("logging_max_file_mb", 10))
        s.logging_retention_days = int(cfg_dict.get("logging_retention_days", 30))
        s.logging_max_total_mb = int(cfg_dict.get("logging_max_total_mb", 200))
        s.logging_auto_rotate = bool(cfg_dict.get("logging_auto_rotate", True))
        s.logging_archive_enabled = bool(cfg_dict.get("logging_archive_enabled", True))
        self._save_settings()
        get_logging_manager().update_config(
            LogConfig(
                enabled=s.logging_enabled,
                level=s.logging_level,
                max_file_mb=s.logging_max_file_mb,
                retention_days=s.logging_retention_days,
                max_total_mb=s.logging_max_total_mb,
                auto_rotate=s.logging_auto_rotate,
                archive_enabled=s.logging_archive_enabled,
            )
        )

    def _on_error_logged(self) -> None:
        if self._current_page_id != "logs" or not self.isVisible():
            self._unseen_errors += 1
            self.sidebar.set_badge("logs", self._unseen_errors)

    # ================================================================== utilities & window geometry
    def _handle_copy_request(self, kind: str, button: object) -> None:
        if kind == "url":
            text = self.manager.public_url or self.home_page.copy_field.full_text()
        else:
            text = self.manager.token
        if isinstance(button, QPushButton):
            self._copy(text, button)

    def _copy(self, text: str, button: QPushButton) -> None:
        if not text:
            return
        QGuiApplication.clipboard().setText(text)
        self._flash(button, tr("home.url.copied"))
        self.toasts.show_toast(tr("toast.copied"), "ok")

    @staticmethod
    def _flash(button: QPushButton, text: str) -> None:
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
            repolish(edit)

    def _confirm(self, title: str, text: str) -> bool:
        return SilentMessageBox.confirm(
            self,
            APP_NAME,
            title,
            text,
            accept_label=tr("common.continue"),
            cancel_label=tr("common.cancel"),
        )

    def _save_settings(self) -> None:
        try:
            self.settings.save()
        except OSError as exc:
            self.manager.log_line.emit(APP, f"✖ Не удалось сохранить настройки: {exc}")

    def _restore_geometry(self) -> None:
        raw_w = self.settings.window_width
        raw_h = self.settings.window_height
        if self.settings.window_x is None and self.settings.window_y is None and (raw_w, raw_h) == (1120, 760):
            raw_w, raw_h = tokens.WINDOW_DEFAULT_W, tokens.WINDOW_DEFAULT_H
        w = max(tokens.WINDOW_MIN_W, raw_w)
        h = max(tokens.WINDOW_MIN_H, raw_h)
        self.resize(w, h)
        if self.settings.window_x is not None and self.settings.window_y is not None:
            screen = QGuiApplication.primaryScreen()
            if screen is not None:
                avail = screen.availableGeometry()
                x = max(avail.left(), min(self.settings.window_x, avail.right() - 200))
                y = max(avail.top(), min(self.settings.window_y, avail.bottom() - 200))
                self.move(x, y)
        if self.settings.window_maximized:
            self.setWindowState(self.windowState() | Qt.WindowState.WindowMaximized)

    def _persist_geometry(self) -> None:
        maximized = bool(self.windowState() & Qt.WindowState.WindowMaximized)
        self.settings.window_maximized = maximized
        if not maximized:
            geo = self.geometry()
            self.settings.window_width = max(tokens.WINDOW_MIN_W, geo.width())
            self.settings.window_height = max(tokens.WINDOW_MIN_H, geo.height())
            self.settings.window_x = geo.x()
            self.settings.window_y = geo.y()
        self._save_settings()

    def resizeEvent(self, event: QResizeEvent) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.toasts.reposition()

    def show_and_raise(self) -> None:
        if self.isMinimized():
            self.showNormal()
        self.show()
        self.raise_()
        self.activateWindow()

    def allow_close(self) -> None:
        self._allow_close = True

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        self._persist_geometry()
        if self._allow_close:
            for sig, slot in (
                (theme.manager().theme_changed, self._on_theme_changed),
                (i18n.language_changed, self._on_language_changed),
            ):
                try:
                    sig.disconnect(slot)
                except (TypeError, RuntimeError):
                    pass
            self._desktop_poll.stop()
            self.servers_page.shutdown()
            self.workspaces_page.shutdown()
            self.extensions_page.shutdown()
            self.devices_page.shutdown()
            self.automation_page.shutdown()
            event.accept()
            return
        event.ignore()
        if self._tray_available and self.settings.minimize_to_tray_on_close:
            self.hide()
        else:
            self.quit_requested.emit()

    def changeEvent(self, event: QEvent) -> None:  # noqa: N802
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange and self.isVisible():
            self.toasts.reposition()
