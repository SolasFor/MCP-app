"""Содержимое вкладки «Прокси»: какие хосты Cloudflare и через какой прокси пускать.

    [x] Пускать хосты Cloudflare через прокси
    Адрес прокси   [socks5://127.0.0.1:1080        ]
    Хосты          [api.trycloudflare.com:443      ]
                   [region1.v2.argotunnel.com:7844 ] …
    [Сохранить] [Проверить] [Список по умолчанию]
    Хост | Напрямую | Через прокси

Заголовок страницы и карточку рисует главное окно (app/ui/main_window.py), здесь — только
поля. Сигнал saved — настройки записаны в proxy.json; окно передаёт их в
ServiceManager.apply_proxy_settings (туннель перезапускается, если работает).
Проверка идёт в фоновых потоках, результаты приходят сигналом (очередь Qt).
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QFormLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from app.core import proxy as px

OK = "✓ доступен"
HINT = (
    "Если в вашем регионе часть хостов Cloudflare недоступна, приложение пустит только эти хосты "
    "через указанный прокси (SOCKS5 или HTTP). Остальной трафик идёт напрямую. Через прокси "
    "туннель работает по протоколу HTTP/2 (TCP)."
)


def _button(text: str, name: str | None = None) -> QPushButton:
    button = QPushButton(text)
    if name:
        button.setObjectName(name)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


class ProxyPage(QWidget):
    saved = pyqtSignal(object)               # ProxySettings
    _probe_done = pyqtSignal(int, int, str)  # строка, колонка, текст
    _check_finished = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._checking = False

        hint = QLabel(HINT)
        hint.setObjectName("Hint")
        hint.setWordWrap(True)
        self._hint_label = hint

        self.enabled = QCheckBox("Пускать хосты Cloudflare через прокси")
        self.enabled.setCursor(Qt.CursorShape.PointingHandCursor)
        self.url = QLineEdit()
        self.url.setPlaceholderText("socks5://127.0.0.1:1080  или  http://логин:пароль@host:port")
        self.hosts = QPlainTextEdit()
        self.hosts.setPlaceholderText("Один хост на строку: host или host:port (по умолчанию 443)")
        self.hosts.setMinimumHeight(110)

        self._url_label = QLabel("Адрес прокси")
        self._hosts_label = QLabel("Хосты")
        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.addRow(self._url_label, self.url)
        form.addRow(self._hosts_label, self.hosts)

        self.save_btn = _button("Сохранить", "Accent")
        self.check_btn = _button("Проверить")
        self.reset_btn = _button("Список по умолчанию", "Ghost")
        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        for button in (self.save_btn, self.check_btn, self.reset_btn):
            buttons.addWidget(button)
        buttons.addStretch(1)

        self.status = QLabel("")
        self.status.setObjectName("Hint")
        self.status.setWordWrap(True)
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Хост", "Напрямую", "Через прокси"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.setMinimumHeight(170)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.hide()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(hint)
        layout.addWidget(self.enabled)
        layout.addLayout(form)
        layout.addLayout(buttons)
        layout.addWidget(self.status)
        layout.addWidget(self.table)

        self.save_btn.clicked.connect(self._save)
        self.check_btn.clicked.connect(self._check)
        self.reset_btn.clicked.connect(self._reset_hosts)
        self.enabled.toggled.connect(self._sync_enabled)
        self._probe_done.connect(self._set_cell)
        self._check_finished.connect(self._on_check_finished)

        self.load(px.load())

    def retranslate(self) -> None:
        """Preserve localized proxy controls across live language switches."""
        from app.ui.i18n import LANG_EN, i18n

        if i18n.language == LANG_EN:
            self._hint_label.setText(
                "If some Cloudflare hosts are blocked in your network, route only those hosts "
                "through a local SOCKS5 or HTTP proxy. Tunnel traffic uses HTTP/2 (TCP)."
            )
            self.enabled.setText("Route Cloudflare hosts through proxy")
            self._url_label.setText("Proxy URL")
            self._hosts_label.setText("Hosts")
            self.url.setPlaceholderText("socks5://127.0.0.1:1080 or http://user:pass@host:port")
            self.hosts.setPlaceholderText("One host per line: host or host:port (default 443)")
            self.save_btn.setText("Save")
            self.check_btn.setText("Check")
            self.reset_btn.setText("Default Hosts")
            self.table.setHorizontalHeaderLabels(["Host", "Direct", "Via Proxy"])
        else:
            self._hint_label.setText(HINT)
            self.enabled.setText("Пускать хосты Cloudflare через прокси")
            self._url_label.setText("Адрес прокси")
            self._hosts_label.setText("Хосты")
            self.url.setPlaceholderText("socks5://127.0.0.1:1080  или  http://логин:пароль@host:port")
            self.hosts.setPlaceholderText("Один хост на строку: host или host:port (по умолчанию 443)")
            self.save_btn.setText("Сохранить")
            self.check_btn.setText("Проверить")
            self.reset_btn.setText("Список по умолчанию")
            self.table.setHorizontalHeaderLabels(["Хост", "Напрямую", "Через прокси"])

    # ------------------------------------------------------------ данные
    def load(self, settings: px.ProxySettings) -> None:
        self.enabled.setChecked(settings.enabled)
        self.url.setText(settings.url)
        self.hosts.setPlainText("\n".join(settings.hosts))
        self._sync_enabled(settings.enabled)

    def current(self) -> px.ProxySettings:
        lines = [line.strip() for line in self.hosts.toPlainText().splitlines() if line.strip()]
        return px.ProxySettings(enabled=self.enabled.isChecked(), url=self.url.text().strip(), hosts=lines)

    def _sync_enabled(self, on: bool) -> None:
        self.url.setEnabled(on)

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
        except OSError as exc:
            self._show_status(f"Не удалось сохранить: {exc}", error=True)
            return
        self._show_status("Сохранено. Если сервисы запущены, туннель перезапустится с новыми настройками."
                          if settings.enabled else "Сохранено. Прокси выключен — все хосты идут напрямую.")
        self.saved.emit(settings)

    def _show_status(self, text: str, error: bool = False) -> None:
        self.status.setText(text)
        self.status.setObjectName("Error" if error else "Hint")
        style = self.status.style()
        style.unpolish(self.status)
        style.polish(self.status)

    # ------------------------------------------------------------ проверка
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
        use_proxy = True
        try:
            settings.endpoint()
        except ValueError as exc:
            use_proxy = False
            self._show_status(f"Проверяю только напрямую: {exc}", error=True)
        else:
            self._show_status("Проверяю…")

        self.table.setRowCount(len(targets))
        for row, (host, port) in enumerate(targets):
            self.table.setItem(row, 0, QTableWidgetItem(f"{host}:{port}"))
            self.table.setItem(row, 1, QTableWidgetItem("…"))
            self.table.setItem(row, 2, QTableWidgetItem("…" if use_proxy else "—"))
        self.table.show()
        self._checking = True
        self.check_btn.setEnabled(False)

        def run() -> None:
            jobs = []
            with ThreadPoolExecutor(max_workers=8) as pool:
                for row, (host, port) in enumerate(targets):
                    jobs.append((row, 1, pool.submit(px.probe, settings, host, port, False)))
                    if use_proxy:
                        jobs.append((row, 2, pool.submit(px.probe, settings, host, port, True)))
                for row, column, future in jobs:
                    error = future.result()
                    self._probe_done.emit(row, column, OK if error is None else f"✕ {error}")
            self._check_finished.emit()

        threading.Thread(target=run, name="proxy-check", daemon=True).start()

    def _set_cell(self, row: int, column: int, text: str) -> None:
        self.table.setItem(row, column, QTableWidgetItem(text))

    def _on_check_finished(self) -> None:
        self._checking = False
        self.check_btn.setEnabled(True)
        direct_fail, proxy_fail = [], []
        for row in range(self.table.rowCount()):
            host = self.table.item(row, 0).text()
            if not self.table.item(row, 1).text().startswith("✓"):
                direct_fail.append(host)
            if self.table.item(row, 2).text().startswith("✕"):
                proxy_fail.append(host)
        if proxy_fail:
            self._show_status("Через прокси недоступны: " + ", ".join(proxy_fail)
                              + ". Проверьте адрес прокси и что он запущен.", error=True)
        elif direct_fail and not self.enabled.isChecked():
            self._show_status("Напрямую недоступны: " + ", ".join(direct_fail)
                              + ". Включите прокси и нажмите «Сохранить».")
        elif direct_fail:
            self._show_status("Напрямую недоступны: " + ", ".join(direct_fail)
                              + ", через прокси — всё доступно.")
        else:
            self._show_status("Все хосты доступны.")
