"""Вкладка «Прокси»: какие хосты Cloudflare и через какой прокси пускать.

    [x] Проксировать хосты Cloudflare
    Адрес прокси   [socks5://127.0.0.1:1080        ]
    Хосты          [api.trycloudflare.com:443      ]
                   [region1.v2.argotunnel.com:7844 ] …
    [Сохранить] [Проверить] [Список по умолчанию]
    Хост | Напрямую | Через прокси

Сигнал saved — настройки записаны; главное окно перезапускает туннель, если он
работает. Проверка идёт в фоновых потоках, результаты приходят сигналом (очередь Qt).
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QFormLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from app.core import proxy as px

OK = "✓ доступен"


class ProxyPage(QWidget):
    saved = pyqtSignal(object)          # ProxySettings
    _probe_done = pyqtSignal(int, int, str)  # строка, колонка, текст
    _check_finished = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("proxyPage")
        self._checking = False

        title = QLabel("Прокси для Cloudflare")
        title.setObjectName("pageTitle")
        hint = QLabel(
            "Если в вашем регионе часть хостов Cloudflare недоступна, приложение пустит "
            "только эти хосты через указанный прокси. Остальной трафик идёт напрямую. "
            "Туннель через прокси работает по протоколу HTTP/2 (TCP).")
        hint.setWordWrap(True)
        hint.setObjectName("muted")

        self.enabled = QCheckBox("Проксировать хосты Cloudflare")
        self.url = QLineEdit()
        self.url.setPlaceholderText("socks5://127.0.0.1:1080  или  http://логин:пароль@host:port")
        self.hosts = QPlainTextEdit()
        self.hosts.setPlaceholderText("Один хост на строку: host или host:port (по умолчанию 443)")
        self.hosts.setMinimumHeight(110)

        form = QFormLayout()
        form.addRow("Адрес прокси", self.url)
        form.addRow("Хосты", self.hosts)

        self.save_btn = QPushButton("Сохранить")
        self.save_btn.setObjectName("primary")
        self.check_btn = QPushButton("Проверить")
        self.reset_btn = QPushButton("Список по умолчанию")
        buttons = QHBoxLayout()
        for button in (self.save_btn, self.check_btn, self.reset_btn):
            buttons.addWidget(button)
        buttons.addStretch(1)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Хост", "Напрямую", "Через прокси"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)
        layout.addWidget(title)
        layout.addWidget(hint)
        layout.addWidget(self.enabled)
        layout.addLayout(form)
        layout.addLayout(buttons)
        layout.addWidget(self.status)
        layout.addWidget(self.table, 1)

        self.save_btn.clicked.connect(self._save)
        self.check_btn.clicked.connect(self._check)
        self.reset_btn.clicked.connect(self._reset_hosts)
        self.enabled.toggled.connect(self._sync_enabled)
        self._probe_done.connect(self._set_cell)
        self._check_finished.connect(self._on_check_finished)

        self.load(px.load())

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
        px.save(settings)
        self._show_status("Сохранено. Туннель перезапустится с новыми настройками." if settings.enabled
                          else "Сохранено. Прокси выключен — все хосты идут напрямую.")
        self.saved.emit(settings)

    def _show_status(self, text: str, error: bool = False) -> None:
        self.status.setText(text)
        self.status.setObjectName("error" if error else "muted")
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)

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
        elif direct_fail:
            self._show_status("Напрямую недоступны: " + ", ".join(direct_fail)
                              + ". Включите прокси для этих хостов и нажмите «Сохранить».")
        else:
            self._show_status("Все хосты доступны.")
