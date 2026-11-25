"""Вкладка «Прокси»: режимы Выключен / Автопоиск / Ручная настройка и диагностика прокси.

По умолчанию прокси выключен (mode="none") без фиктивного 127.0.0.1:1080.
Все проверки выполняются в фоновых потоках и логируются через LoggingManager.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core import proxy as px
from app.core.logging_manager import get_logging_manager
from app.ui.components.safe_combo import SafeComboBox
from app.ui.i18n import LANG_EN, i18n, tr


def _button(text: str, name: str | None = None) -> QPushButton:
    button = QPushButton(text)
    if name:
        button.setObjectName(name)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


class ProxyPage(QWidget):
    saved = pyqtSignal(object)                    # ProxySettings
    _probe_done = pyqtSignal(int, list)           # row, [col1, col2, col3, col4]
    _check_finished = pyqtSignal()
    _detect_finished = pyqtSignal(object)         # px.AutoDetectResult

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._checking = False
        self._detecting = False

        self._hint_label = QLabel()
        self._hint_label.setObjectName("Hint")
        self._hint_label.setWordWrap(True)

        self.mode_combo = SafeComboBox()
        self.mode_combo.addItem("", px.PROXY_MODE_NONE)
        self.mode_combo.addItem("", px.PROXY_MODE_AUTO)
        self.mode_combo.addItem("", px.PROXY_MODE_MANUAL)
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)

        self.scheme_combo = SafeComboBox()
        self.scheme_combo.addItem("SOCKS5H (DNS через прокси)", "socks5h")
        self.scheme_combo.addItem("SOCKS5 (локальный DNS)", "socks5")
        self.scheme_combo.addItem("HTTP CONNECT", "http")

        self.host_edit = QLineEdit()
        self.host_edit.setObjectName("UiInput")
        self.host_edit.setPlaceholderText("127.0.0.1 или proxy.corp.local")

        self.port_spin = QSpinBox()
        self.port_spin.setObjectName("UiInput")
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(1080)

        self.username_edit = QLineEdit()
        self.username_edit.setObjectName("UiInput")
        self.username_edit.setPlaceholderText("необязательно")

        self.password_edit = QLineEdit()
        self.password_edit.setObjectName("UiInput")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("необязательно (DPAPI)")
        self.password_eye = _button(tr("conn.token.show"), "Ghost")
        self.password_eye.clicked.connect(self._toggle_password_eye)
        pw_row = QHBoxLayout()
        pw_row.addWidget(self.password_edit, 1)
        pw_row.addWidget(self.password_eye)

        self.hosts = QPlainTextEdit()
        self.hosts.setObjectName("UiInput")
        self.hosts.setMinimumHeight(96)

        self._manual_box = QWidget()
        manual_form = QFormLayout(self._manual_box)
        manual_form.setContentsMargins(0, 0, 0, 0)
        manual_form.setSpacing(6)
        self._scheme_lbl = QLabel()
        self._host_lbl = QLabel()
        self._port_lbl = QLabel()
        self._user_lbl = QLabel()
        self._pass_lbl = QLabel()
        manual_form.addRow(self._scheme_lbl, self.scheme_combo)
        manual_form.addRow(self._host_lbl, self.host_edit)
        manual_form.addRow(self._port_lbl, self.port_spin)
        manual_form.addRow(self._user_lbl, self.username_edit)
        manual_form.addRow(self._pass_lbl, pw_row)

        top_form = QFormLayout()
        top_form.setContentsMargins(0, 0, 0, 0)
        top_form.setSpacing(6)
        self._mode_lbl = QLabel()
        self._hosts_lbl = QLabel()
        top_form.addRow(self._mode_lbl, self.mode_combo)
        top_form.addRow(self._hosts_lbl, self.hosts)

        self.detect_btn = _button("", "Ghost")
        self.detect_btn.clicked.connect(self._detect_now)
        self.save_btn = _button("", "Accent")
        self.save_btn.clicked.connect(self._save)
        self.check_btn = _button("")
        self.check_btn.clicked.connect(self._check)
        self.reset_btn = _button("", "Ghost")
        self.reset_btn.clicked.connect(self._reset_hosts)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        for button in (self.save_btn, self.check_btn, self.detect_btn, self.reset_btn):
            buttons.addWidget(button)
        buttons.addStretch(1)

        self.status = QLabel("")
        self.status.setObjectName("Hint")
        self.status.setWordWrap(True)
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self.table = QTableWidget(0, 5)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.setMinimumHeight(180)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.hide()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(self._hint_label)
        layout.addLayout(top_form)
        layout.addWidget(self._manual_box)
        layout.addLayout(buttons)
        layout.addWidget(self.status)
        layout.addWidget(self.table)

        self._probe_done.connect(self._set_row)
        self._check_finished.connect(self._on_check_finished)
        self._detect_finished.connect(self._on_detect_finished)

        self.retranslate()
        self.load(px.load())

    def _toggle_password_eye(self) -> None:
        vis = self.password_edit.echoMode() == QLineEdit.EchoMode.Password
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Normal if vis else QLineEdit.EchoMode.Password)
        self.password_eye.setText(tr("conn.token.hide" if vis else "conn.token.show"))

    def retranslate(self) -> None:
        is_en = i18n.language == LANG_EN
        if is_en:
            self._hint_label.setText(
                "Proxy defaults to Off (direct). Auto mode scans system WinINET/WinHTTP/ENV/PAC and verified local VPN ports "
                "without silent direct fallback. Manual mode supports SOCKS5H, SOCKS5, and HTTP CONNECT with DPAPI credentials."
            )
            modes = {
                px.PROXY_MODE_NONE: "Off (direct connection)",
                px.PROXY_MODE_AUTO: "Auto-detect system / local proxy",
                px.PROXY_MODE_MANUAL: "Manual proxy configuration",
            }
            self._mode_lbl.setText("Proxy mode")
            self._scheme_lbl.setText("Protocol")
            self._host_lbl.setText("Host")
            self._port_lbl.setText("Port")
            self._user_lbl.setText("Username")
            self._pass_lbl.setText("Password")
            self._hosts_lbl.setText("Routed hosts")
            self.hosts.setPlaceholderText("One host per line: host or host:port (default 443)")
            self.detect_btn.setText("Detect now")
            self.save_btn.setText("Save")
            self.check_btn.setText("Diagnose")
            self.reset_btn.setText("Default Hosts")
            self.table.setHorizontalHeaderLabels(["Host", "Direct", "Via Proxy", "Latency", "Details"])
        else:
            self._hint_label.setText(
                "По умолчанию прокси выключен (прямое соединение). В режиме «Автопоиск» проверяются ENV/WinINET/WinHTTP/PAC "
                "и локальные VPN-порты с реальным handshake (без молчаливого отката на direct). Ручной режим поддерживает SOCKS5H, SOCKS5 и HTTP CONNECT."
            )
            modes = {
                px.PROXY_MODE_NONE: "Выключен (прямое соединение)",
                px.PROXY_MODE_AUTO: "Автопоиск системного / локального прокси",
                px.PROXY_MODE_MANUAL: "Ручная настройка",
            }
            self._mode_lbl.setText("Режим прокси")
            self._scheme_lbl.setText("Протокол")
            self._host_lbl.setText("Хост")
            self._port_lbl.setText("Порт")
            self._user_lbl.setText("Логин")
            self._pass_lbl.setText("Пароль")
            self._hosts_lbl.setText("Хосты")
            self.hosts.setPlaceholderText("Один хост на строку: host или host:port (по умолчанию 443)")
            self.detect_btn.setText("Найти прокси")
            self.save_btn.setText("Сохранить")
            self.check_btn.setText("Диагностика")
            self.reset_btn.setText("Список по умолчанию")
            self.table.setHorizontalHeaderLabels(["Хост", "Напрямую", "Через прокси", "Задержка", "Детали"])

        self.mode_combo.blockSignals(True)
        for idx in range(self.mode_combo.count()):
            m = str(self.mode_combo.itemData(idx) or "")
            if m in modes:
                self.mode_combo.setItemText(idx, modes[m])
        self.mode_combo.blockSignals(False)
        vis = self.password_edit.echoMode() == QLineEdit.EchoMode.Normal
        self.password_eye.setText(tr("conn.token.hide" if vis else "conn.token.show"))

    def load(self, settings: px.ProxySettings) -> None:
        self.mode_combo.blockSignals(True)
        m_idx = self.mode_combo.findData(settings.mode)
        if m_idx >= 0:
            self.mode_combo.setCurrentIndex(m_idx)
        self.mode_combo.blockSignals(False)

        scheme = (settings.scheme or "socks5h").lower()
        host = settings.host
        port = settings.port
        user = settings.username
        password = settings.password
        if settings.url and not host:
            p = urlsplit(settings.url)
            scheme = (p.scheme or scheme).lower()
            host = p.hostname or ""
            port = p.port or (1080 if scheme.startswith("socks") else 8080)
            user = user or (p.username or "")
            password = password or (p.password or "")

        s_idx = self.scheme_combo.findData(scheme if scheme in ("socks5h", "socks5", "http") else "socks5h")
        if s_idx >= 0:
            self.scheme_combo.setCurrentIndex(s_idx)
        self.host_edit.setText(host)
        self.port_spin.setValue(max(1, min(65535, int(port or 1080))))
        self.username_edit.setText(user)
        self.password_edit.setText(password)
        self.hosts.setPlainText("\n".join(settings.hosts or px.DEFAULT_HOSTS))
        self._sync_mode_ui()

    def _on_mode_changed(self, _index: int) -> None:
        self._sync_mode_ui()

    def _sync_mode_ui(self) -> None:
        mode = str(self.mode_combo.currentData() or px.PROXY_MODE_NONE)
        self._manual_box.setVisible(mode == px.PROXY_MODE_MANUAL)
        self.hosts.setEnabled(mode != px.PROXY_MODE_NONE)

    def current(self) -> px.ProxySettings:
        mode = str(self.mode_combo.currentData() or px.PROXY_MODE_NONE)
        lines = [line.strip() for line in self.hosts.toPlainText().splitlines() if line.strip()]
        if mode == px.PROXY_MODE_MANUAL:
            scheme = str(self.scheme_combo.currentData() or "socks5h")
            host = self.host_edit.text().strip()
            port = int(self.port_spin.value())
            username = self.username_edit.text().strip()
            password = self.password_edit.text()
            return px.ProxySettings(
                mode=px.PROXY_MODE_MANUAL,
                scheme=scheme,
                host=host,
                port=port,
                username=username,
                password=password,
                hosts=lines or list(px.DEFAULT_HOSTS),
            )
        return px.ProxySettings(
            mode=mode,
            hosts=lines or list(px.DEFAULT_HOSTS),
        )

    def _reset_hosts(self) -> None:
        self.hosts.setPlainText("\n".join(px.DEFAULT_HOSTS))

    def _save(self) -> None:
        settings = self.current()
        errors = settings.validate()
        if errors:
            self._show_status("\n".join(errors), error=True)
            return
        try:
            px.save(settings)
            get_logging_manager().info(
                "proxy",
                f"Proxy settings saved: mode={settings.mode} enabled={settings.enabled} "
                f"scheme={settings.scheme} host={settings.host or '-'} port={settings.port}",
                event_code="proxy_saved",
            )
        except OSError as exc:
            self._show_status(f"Не удалось сохранить: {exc}", error=True)
            return
        if settings.mode == px.PROXY_MODE_NONE:
            self._show_status("Сохранено. Прокси выключен — все соединения идут напрямую.")
        elif settings.mode == px.PROXY_MODE_AUTO:
            self._show_status("Сохранено. Включён режим автопоиска прокси (проверка при запуске/диагностике).")
        else:
            self._show_status("Сохранено. Ручной прокси применён (перезапустит туннель при необходимости).")
        self.saved.emit(settings)

    def _show_status(self, text: str, error: bool = False) -> None:
        self.status.setText(text)
        self.status.setObjectName("Error" if error else "Hint")
        style = self.status.style()
        if style is not None:
            style.unpolish(self.status)
            style.polish(self.status)

    def _detect_now(self) -> None:
        if self._detecting:
            return
        self._detecting = True
        self.detect_btn.setEnabled(False)
        self._show_status("Проверяю системные/локальные прокси с тестовым handshake…")

        def run() -> None:
            res = px.discover_working_proxy()
            self._detect_finished.emit(res)

        threading.Thread(target=run, name="proxy-detect", daemon=True).start()

    def _on_detect_finished(self, result_obj: object) -> None:
        self._detecting = False
        self.detect_btn.setEnabled(True)
        if not isinstance(result_obj, px.AutoDetectResult):
            self._show_status("Системные или локальные прокси не найдены.", error=True)
            return
        candidates = result_obj.candidates
        working = [c for c in candidates if c.working]
        if not candidates:
            note = f" ({'; '.join(result_obj.notes)})" if result_obj.notes else ""
            self._show_status(f"Системные или локальные прокси не найдены{note}.")
            return
        if not working:
            summary = "; ".join(f"{c.scheme}://{c.host}:{c.port} ({c.source}): {c.reason}" for c in candidates[:3])
            self._show_status(f"Найдены кандидаты, но ни один не прошёл handshake: {summary}", error=True)
            return
        best = result_obj.selected or working[0]
        lat = f"{best.latency_ms:.0f} мс" if best.latency_ms is not None else "—"
        self._show_status(
            f"Рабочий прокси найден [{best.source}]: {best.scheme}://{best.host}:{best.port} "
            f"({lat}) — {best.reason}"
        )

    def _check(self) -> None:
        if self._checking:
            return
        settings = self.current()
        try:
            targets = settings.targets()
        except ValueError as exc:
            self._show_status(str(exc), error=True)
            return
        if not targets:
            self._show_status("Список хостов пуст.", error=True)
            return
        mode = settings.mode
        self._show_status("Выполняется фоновая диагностика соединений и прокси…")

        self.table.setRowCount(len(targets))
        for row, (host, port) in enumerate(targets):
            for col, txt in enumerate((f"{host}:{port}", "…", "…" if mode != px.PROXY_MODE_NONE else "—", "…", "")):
                self.table.setItem(row, col, QTableWidgetItem(txt))
        self.table.show()
        self._checking = True
        self.check_btn.setEnabled(False)

        def run() -> None:
            effective = settings
            auto_note = ""
            if mode == px.PROXY_MODE_AUTO:
                det = px.discover_working_proxy()
                if det.selected is not None:
                    best = det.selected
                    effective = px.ProxySettings(
                        mode=px.PROXY_MODE_MANUAL,
                        scheme=best.scheme,
                        host=best.host,
                        port=best.port,
                        hosts=settings.hosts,
                        detected_url=f"{best.scheme}://{best.host}:{best.port}",
                        detected_source=best.source,
                    )
                    auto_note = f"auto:{best.source}"
            use_proxy = mode != px.PROXY_MODE_NONE and not effective.validate()
            with ThreadPoolExecutor(max_workers=8) as pool:
                direct_futs = {
                    row: pool.submit(px.diagnose_target, effective, h, p, via_proxy=False)
                    for row, (h, p) in enumerate(targets)
                }
                proxy_futs = {
                    row: pool.submit(px.diagnose_target, effective, h, p, via_proxy=True)
                    for row, (h, p) in enumerate(targets)
                } if use_proxy else {}
                for row in range(len(targets)):
                    d_ok, d_msg, d_info = direct_futs[row].result()
                    if row in proxy_futs:
                        p_ok, p_msg, p_info = proxy_futs[row].result()
                        p_type = p_info.get("proxy_type") or effective.scheme.upper()
                        lat = p_info.get("latency_ms")
                        lat_txt = f"{lat:.0f} мс" if isinstance(lat, (int, float)) else "—"
                        p_cell = f"✓ {p_type}" if p_ok else f"✕ {p_type}"
                        det_txt = f"{auto_note} {p_msg}".strip()
                    else:
                        d_lat = d_info.get("latency_ms")
                        lat_txt = f"{d_lat:.0f} мс" if isinstance(d_lat, (int, float)) else "—"
                        p_cell = "— (выкл)" if mode == px.PROXY_MODE_NONE else "✕ не найден"
                        det_txt = d_msg
                    d_cell = "✓ OK" if d_ok else f"✕ {d_msg[:28]}"
                    self._probe_done.emit(row, [d_cell, p_cell, lat_txt, det_txt])
            self._check_finished.emit()

        threading.Thread(target=run, name="proxy-check", daemon=True).start()

    def _set_row(self, row: int, cols: list) -> None:
        for offset, text in enumerate(cols, start=1):
            self.table.setItem(row, offset, QTableWidgetItem(str(text)))

    def _on_check_finished(self) -> None:
        self._checking = False
        self.check_btn.setEnabled(True)
        proxy_fail = []
        direct_fail = []
        for row in range(self.table.rowCount()):
            host = self.table.item(row, 0).text()
            if not self.table.item(row, 1).text().startswith("✓"):
                direct_fail.append(host)
            p_cell = self.table.item(row, 2).text()
            if p_cell.startswith("✕"):
                proxy_fail.append(host)
        if proxy_fail:
            self._show_status("Через прокси есть ошибки: " + ", ".join(proxy_fail), error=True)
        elif direct_fail and self.current().mode == px.PROXY_MODE_NONE:
            self._show_status("Напрямую недоступны: " + ", ".join(direct_fail) + ". Включите автопоиск или ручной прокси.")
        else:
            self._show_status("Диагностика завершена.")

    def diagnostics_snapshot(self) -> dict[str, object]:
        rows = []
        for row in range(self.table.rowCount()):
            rows.append({
                "host": self.table.item(row, 0).text() if self.table.item(row, 0) else "",
                "direct": self.table.item(row, 1).text() if self.table.item(row, 1) else "",
                "via_proxy": self.table.item(row, 2).text() if self.table.item(row, 2) else "",
                "latency": self.table.item(row, 3).text() if self.table.item(row, 3) else "",
                "details": self.table.item(row, 4).text() if self.table.item(row, 4) else "",
            })
        cfg = self.current()
        return {
            "mode": cfg.mode,
            "enabled": cfg.enabled,
            "scheme": cfg.scheme,
            "host": cfg.host,
            "port": cfg.port,
            "hosts": list(cfg.hosts),
            "last_check_status": self.status.text(),
            "last_check_table": rows,
        }
