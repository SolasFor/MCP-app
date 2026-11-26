"""Инструкция «Как подключить свой домен» (именованный туннель Cloudflare).

Команды собираются под эту машину: полный путь к встроенному cloudflared.exe (на
чистой Windows его нет в PATH), папка .cloudflared и порт сервера из настроек.
Тот же текст для чтения в репозитории — docs/custom-domain.md.
"""
from __future__ import annotations

import html
from pathlib import Path

from PyQt6.QtCore import QTimer, QUrl
from PyQt6.QtGui import QDesktopServices, QGuiApplication, QTextCursor
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QTextBrowser, QVBoxLayout, QWidget

from app import APP_NAME
from app.config import PROVIDER_CF_NAMED, PROVIDER_CF_QUICK, PROVIDER_NGROK, PROVIDER_TAILSCALE, Settings
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
    step = f"color:{theme.TEXT_STRONG}; font-size:16px; font-weight:600; margin-top:20px;"
    note = f"color:{theme.TEXT_MUTED};"

    def pre(text: str) -> str:
        return f'<pre style="{code}">{text}</pre>'

    template = html.escape(config_template(settings))
    return f"""
<div style="color:{theme.TEXT}; font-family:{ui_font}; font-size:13px; line-height:1.45;">
<table width="100%" cellspacing="0" cellpadding="12" bgcolor="{theme.SURFACE}"><tr><td><b>Перед началом</b><p>Свой домен даёт постоянный адрес вроде <b>https://{EXAMPLE_HOST}{html.escape(settings.mcp_path)}</b>: он не меняется
при перезапуске, поддерживает SSE и не зависит от trycloudflare.com. Настройка делается один раз.
Нужен домен и аккаунт Cloudflare.</p></td></tr></table>

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
<p>«Подключение» → Cloudflare Named Tunnel → «⋯» → «Настроить» → введите <code>{EXAMPLE_HOST}</code> → «Сохранить». Выберите Named Tunnel и запустите сервис на главной странице. Адрес для клиентов будет <b>https://{EXAMPLE_HOST}{html.escape(settings.mcp_path)}</b>, токен владельца — прежний.</p>

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


_GUIDE_TITLES = {
    PROVIDER_CF_NAMED: ("Cloudflare Named Tunnel", "Постоянный HTTPS-адрес на собственном домене"),
    PROVIDER_CF_QUICK: ("Cloudflare Quick Tunnel", "Быстрое подключение без собственного домена"),
    PROVIDER_NGROK: ("ngrok", "Публичный HTTPS-адрес через ngrok Agent"),
    PROVIDER_TAILSCALE: ("Tailscale Funnel", "Публичный HTTPS-адрес на домене ts.net"),
}


def provider_guide_html(settings: Settings, cloudflared: str | None, provider_id: str) -> str:
    if provider_id == PROVIDER_CF_NAMED:
        return guide_html(settings, cloudflared)
    endpoint = html.escape(settings.mcp_path)
    local = html.escape(f"http://{settings.local_host()}:{settings.server_port}")
    if provider_id == PROVIDER_NGROK:
        intro = "Нужен аккаунт ngrok и установленный агент. Для OAuth желательно закрепить адрес."
        steps = [
            ("Установите агент", 'Откройте <a href="https://ngrok.com/download/windows">загрузку ngrok для Windows</a>. Установите агент и проверьте в PowerShell: <code>ngrok version</code>.'),
            ("Получите Authtoken", 'Войдите в <a href="https://dashboard.ngrok.com/">личный кабинет ngrok</a> и найдите Authtoken. Это не MCP Owner Token. Не публикуйте его и не отправляйте в чат.'),
            ("Настройте MCP App", 'В строке ngrok откройте ⋯ → Настроить. Вставьте Authtoken в защищённое поле. При необходимости укажите путь к ngrok.exe и закреплённый домен из кабинета. Local API URL оставьте по умолчанию, если не меняли настройки агента. Нажмите Сохранить.'),
            ("Проверьте и запустите", 'Откройте ⋯ → Проверить, затем Выбрать и запустите сервер на главной странице. Приложение запускает агент самостоятельно; отдельный процесс ngrok запускать не нужно.'),
            ("Подключите AI-клиент", f'Скопируйте фактический публичный MCP URL с главной страницы (путь <code>{endpoint}</code>) и добавьте его в клиент. При изменении адреса OAuth может потребовать повторной авторизации.'),
        ]
        trouble = "Если агент не найден, укажите путь к EXE. При ошибке авторизации проверьте Authtoken; при ошибке домена — его принадлежность аккаунту. SOCKS5 для ngrok CLI не поддерживается."
        docs = "https://ngrok.com/docs/start"
    elif provider_id == PROVIDER_TAILSCALE:
        intro = "Нужен аккаунт Tailscale, подключённый Windows-узел и разрешение Funnel. Funnel открывает маршрут в публичный интернет, в отличие от Serve."
        steps = [
            ("Установите Tailscale", 'Скачайте <a href="https://tailscale.com/download/windows">Tailscale для Windows</a>, установите и войдите в свою сеть (tailnet). Проверьте <code>tailscale status</code>.'),
            ("Разрешите Funnel", 'В <a href="https://login.tailscale.com/admin/dns">панели DNS</a> включите MagicDNS и HTTPS-сертификаты. В политике доступа tailnet разрешите Funnel нужному узлу через атрибут <code>funnel</code>. Если у вас нет прав администратора, обратитесь к владельцу tailnet.'),
            ("Настройте MCP App", 'В строке Tailscale Funnel откройте ⋯ → Настроить. Выберите публичный порт 443 (либо 8443 или 10000). DNS-имя оставьте для автоопределения, путь к tailscale.exe укажите только при необходимости. Сохраните.'),
            ("Проверьте и запустите", 'Откройте ⋯ → Проверить, затем Выбрать и запустите сервер. MCP App управляет своим маршрутом Funnel самостоятельно. Не сбрасывайте другие маршруты Tailscale.'),
            ("Подключите AI-клиент", f'Скопируйте фактический HTTPS MCP URL на главной странице (путь <code>{endpoint}</code>). При нестандартном порте он входит в URL. Используйте OAuth или токен владельца согласно возможностям клиента.'),
        ]
        trouble = "Если Funnel не запускается, проверьте вход в tailnet, разрешение funnel, MagicDNS, HTTPS и доступность CLI. Прокси-мост MCP App для системного транспорта Tailscale не используется."
        docs = "https://tailscale.com/docs/features/tailscale-funnel"
    else:
        intro = "Не требуется домен или аккаунт Cloudflare. Публичный адрес может измениться после перезапуска."
        steps = [
            ("Проверьте cloudflared", "Приложение использует встроенный cloudflared или установленный агент. Откройте ⋯ → Проверить."),
            ("Выберите транспорт", "Нажмите Выбрать в строке Quick Tunnel. Отдельная конфигурация домена не требуется."),
            ("Запустите сервер", f"На главной странице запустите сервис. Туннель направит запросы на <code>{local}</code>."),
            ("Подключите AI-клиент", f"Скопируйте выданный MCP URL (путь <code>{endpoint}</code>). Если адрес изменился, обновите подключение и авторизуйтесь повторно."),
        ]
        trouble = "Если туннель не запускается, проверьте интернет-соединение и журнал приложения. Для постоянного адреса используйте Named Tunnel или другой стабильный транспорт."
        docs = "https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/"
    sections = "".join(
        f'<h3 style="color:{theme.TEXT_STRONG}; margin-top:20px;">{i:02d} · {title}</h3><p>{body}</p>'
        for i, (title, body) in enumerate(steps, 1)
    )
    return f"""
<div style="color:{theme.TEXT}; font-family:{theme.FONT_UI}; font-size:13px;">
<table width="100%" cellspacing="0" cellpadding="12" bgcolor="{theme.SURFACE}"><tr><td>
<b>Перед началом</b><p>{intro}</p></td></tr></table>
{sections}
<h3 style="color:{theme.TEXT_STRONG}; margin-top:20px;">Если не заработало</h3>
<p>{trouble}</p>
<p style="color:{theme.TEXT_MUTED};">Публичный маршрут не заменяет авторизацию MCP. Не отключайте защиту сервера.</p>
<p><a href="{docs}">Официальная документация</a></p>
</div>"""


class DomainGuideDialog(SilentDialog):
    def __init__(self, settings: Settings, cloudflared: str | None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self._cloudflared = cloudflared
        self._provider_id = PROVIDER_CF_NAMED
        self.setWindowTitle(f"{APP_NAME} — как подключить свой домен")
        self.setModal(False)
        self.resize(760, 650)
        self.setMinimumSize(540, 420)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        self._title = QLabel()
        self._title.setObjectName("SectionTitle")
        self._subtitle = QLabel()
        self._subtitle.setObjectName("Hint")
        self._subtitle.setWordWrap(True)
        layout.addWidget(self._title)
        layout.addWidget(self._subtitle)

        self._browser = QTextBrowser()
        self._browser.setOpenExternalLinks(True)
        self._browser.setFrameShape(QTextBrowser.Shape.NoFrame)
        document = self._browser.document()
        if document is not None:
            document.setDocumentMargin(4)
        layout.addWidget(self._browser, 1)

        row = QHBoxLayout()
        row.setSpacing(8)
        self._copy_template = self._button("Копировать шаблон config.yml", "Accent")
        self._copy_template.clicked.connect(self._on_copy_template)
        self._open_folder = self._button("Открыть папку .cloudflared")
        self._open_folder.clicked.connect(self._on_open_folder)
        close = self._button("Закрыть", "Ghost")
        close.clicked.connect(self.close)
        row.addWidget(self._copy_template)
        row.addWidget(self._open_folder)
        row.addStretch(1)
        row.addWidget(close)
        layout.addLayout(row)
        self.set_provider(PROVIDER_CF_NAMED)

    def set_provider(self, provider_id: str) -> None:
        self._provider_id = provider_id
        title, subtitle = _GUIDE_TITLES[provider_id]
        self.setWindowTitle(f'{APP_NAME} — {title}')
        self._title.setText(title)
        self._subtitle.setText(subtitle)
        named = provider_id == PROVIDER_CF_NAMED
        self._copy_template.setVisible(named)
        self._open_folder.setVisible(named)
        self.apply_theme()
        self._browser.moveCursor(QTextCursor.MoveOperation.Start)

    @staticmethod
    def _button(text: str, name: str | None = None) -> QPushButton:
        button = QPushButton(text)
        if name:
            button.setObjectName(name)
        return button

    def _on_copy_template(self) -> None:
        clipboard = QGuiApplication.clipboard()
        if clipboard is None:
            return
        clipboard.setText(config_template(self.settings))
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
        scroll = self._browser.verticalScrollBar()
        position = scroll.value() if scroll is not None else 0
        self._browser.setHtml(provider_guide_html(self.settings, self._cloudflared, self._provider_id))
        if scroll is not None:
            scroll.setValue(position)
