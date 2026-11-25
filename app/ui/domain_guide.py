"""Инструкция «Как подключить свой домен» (именованный туннель Cloudflare).

Команды собираются под эту машину: полный путь к встроенному cloudflared.exe (на
чистой Windows его нет в PATH), папка .cloudflared и порт сервера из настроек.
Тот же текст для чтения в репозитории — docs/custom-domain.md.
"""
from __future__ import annotations

import html
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, QUrl
from PyQt6.QtGui import QDesktopServices, QGuiApplication
from PyQt6.QtWidgets import QHBoxLayout, QPushButton, QTextBrowser, QVBoxLayout, QWidget

from app import APP_NAME
from app.config import Settings
from app.ui import theme
from app.ui.components.silent_dialog import SilentDialog

TUNNEL_NAME = "mcp-app"
EXAMPLE_HOST = "mcp.example.com"


def _cloudflared_cmd(exe: str | None) -> str:
    """Как вызвать cloudflared в PowerShell."""
    return f'& "{exe}"' if exe else "cloudflared"


def config_template(settings: Settings, host: str = EXAMPLE_HOST) -> str:
    folder = Path(settings.cloudflared_config).expanduser().parent
    return (
        "# config.yml именованного туннеля для MCP app\n"
        "# Замените <UUID> на ID из `cloudflared tunnel create`, а домен — на свой.\n"
        "tunnel: <UUID>\n"
        f"credentials-file: {folder / '<UUID>.json'}\n"
        "\n"
        "ingress:\n"
        f"  - hostname: {host}\n"
        f"    service: http://{settings.local_host()}:{settings.server_port}\n"
        "  - service: http_status:404\n"
    )


def guide_html(settings: Settings, cloudflared: str | None) -> str:
    cmd = html.escape(_cloudflared_cmd(cloudflared))
    config_path = html.escape(str(Path(settings.cloudflared_config).expanduser()))
    folder = html.escape(str(Path(settings.cloudflared_config).expanduser().parent))
    mono = theme.FONT_MONO.replace('"', "'")
    ui_font = theme.FONT_UI.replace('"', "'")
    code = (
        f"background:{theme.SURFACE}; color:{theme.TEXT_STRONG}; font-family:{mono}; "
        f"font-size:12px; padding:8px 10px; border:1px solid {theme.HAIRLINE}; border-radius:6px;"
    )
    step = f"color:{theme.TEXT_STRONG}; font-weight:600; margin-top:14px;"
    note = f"color:{theme.TEXT_MUTED};"

    def pre(text: str) -> str:
        return f'<pre style="{code}">{text}</pre>'

    template = html.escape(config_template(settings))
    return f"""
<div style="color:{theme.TEXT}; font-family:{ui_font}; font-size:13px; line-height:1.45;">
<p style="{note}">Свой домен даёт постоянный адрес вроде <b>https://{EXAMPLE_HOST}/mcp</b>: он не меняется
при перезапуске, поддерживает SSE и не зависит от trycloudflare.com. Настройка делается один раз,
минут за 10. Нужен домен и бесплатный аккаунт Cloudflare.</p>

<p style="{step}">1. Добавьте домен в Cloudflare</p>
<p>Зарегистрируйтесь на <a href="https://dash.cloudflare.com/sign-up">dash.cloudflare.com</a>, нажмите
<b>Add a domain</b> и выберите бесплатный тариф (Free). У регистратора домена замените
NS-серверы на те, что покажет Cloudflare, и дождитесь статуса <b>Active</b>
(обычно от пары минут до нескольких часов).</p>

<p style="{step}">2. Войдите в Cloudflare из cloudflared</p>
<p>Откройте PowerShell и выполните (cloudflared уже встроен в приложение, ставить не нужно):</p>
{pre(f"{cmd} tunnel login")}
<p>Откроется браузер: выберите свой домен и нажмите <b>Authorize</b>. В папке
<code>{folder}</code> появится <code>cert.pem</code>.</p>

<p style="{step}">3. Создайте туннель</p>
{pre(f"{cmd} tunnel create {TUNNEL_NAME}")}
<p>Команда напечатает ID туннеля (UUID) и создаст файл ключей <code>&lt;UUID&gt;.json</code> в той же
папке. Этот файл — как пароль: никому не передавайте.</p>

<p style="{step}">4. Привяжите адрес к туннелю</p>
{pre(f"{cmd} tunnel route dns {TUNNEL_NAME} {EXAMPLE_HOST}")}
<p>Вместо <code>{EXAMPLE_HOST}</code> — ваш поддомен. Cloudflare сам создаст DNS-запись (CNAME).</p>

<p style="{step}">5. Создайте config.yml</p>
<p>Приложение ищет его здесь: <code>{config_path}</code>. Нажмите «Копировать шаблон
 config.yml» ниже, вставьте в Блокнот, подставьте свой UUID и домен и сохраните как
<code>config.yml</code> (в Блокноте выберите «Тип файла: все файлы», иначе получится config.yml.txt).</p>
{pre(template)}

<p style="{step}">6. Включите свой домен в приложении</p>
<p>«Подключение» → «Свой домен» → введите <code>{EXAMPLE_HOST}</code> → «Сохранить» →
«Запустить». Адрес для клиентов будет <b>https://{EXAMPLE_HOST}/mcp</b>, токен — прежний.</p>

<p style="{step}">Если не заработало</p>
<ul>
<li>«Не найден конфиг туннеля» — файл не в той папке или сохранён как config.yml.txt.</li>
<li>«… нет в ingress config.yml» — адрес в приложении и hostname в config.yml должны совпадать.</li>
<li>Туннель не подключается — нужен исходящий доступ к Cloudflare на порт 7844 (брандмауэр, роутер, VPN).</li>
<li>Клиент получает 1033 или 530 — туннель в приложении не запущен или DNS-запись из шага 4 ещё не создана.</li>
</ul>
<p style="{note}">Подробнее: <a href="https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/">
документация Cloudflare про локальные туннели</a>.</p>
</div>
"""


class DomainGuideDialog(SilentDialog):
    def __init__(self, settings: Settings, cloudflared: str | None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self._cloudflared = cloudflared
        self.setWindowTitle(f"{APP_NAME} — как подключить свой домен")
        self.setModal(False)
        self.resize(740, 640)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        self._browser = QTextBrowser()
        self._browser.setOpenExternalLinks(True)
        self._browser.setFrameShape(QTextBrowser.Shape.NoFrame)
        self._browser.document().setDocumentMargin(4)
        self.apply_theme()
        layout.addWidget(self._browser, 1)

        row = QHBoxLayout()
        row.setSpacing(8)
        self._copy_template = self._button("Копировать шаблон config.yml", "Accent")
        self._copy_template.clicked.connect(self._on_copy_template)
        open_folder = self._button("Открыть папку .cloudflared")
        open_folder.clicked.connect(self._on_open_folder)
        close = self._button("Закрыть", "Ghost")
        close.clicked.connect(self.close)
        row.addWidget(self._copy_template)
        row.addWidget(open_folder)
        row.addStretch(1)
        row.addWidget(close)
        layout.addLayout(row)

    @staticmethod
    def _button(text: str, name: str | None = None) -> QPushButton:
        button = QPushButton(text)
        if name:
            button.setObjectName(name)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        return button

    def _on_copy_template(self) -> None:
        QGuiApplication.clipboard().setText(config_template(self.settings))
        original = "Копировать шаблон config.yml"
        self._copy_template.setText("✓ Скопировано")
        QTimer.singleShot(1500, lambda: self._copy_template.setText(original))

    def _on_open_folder(self) -> None:
        folder = Path(self.settings.cloudflared_config).expanduser().parent
        try:
            folder.mkdir(parents=True, exist_ok=True)
        except OSError:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def apply_theme(self) -> None:
        self._browser.setHtml(guide_html(self.settings, self._cloudflared))
