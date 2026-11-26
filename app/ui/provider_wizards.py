"""Setup & diagnostics dialogs for ngrok and Tailscale Funnel."""
from __future__ import annotations

from typing import Any

from PyQt6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.tunnels import (
    PROVIDER_NGROK,
    PROVIDER_TAILSCALE,
    ConnectionManager,
)
from app.core.tunnels.ngrok import DEFAULT_NGROK_API_URL
from app.core.tunnels.tailscale import ALLOWED_FUNNEL_PORTS
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.silent_dialog import SilentDialog, SilentMessageBox
from app.ui.i18n import tr


class ProviderConfigDialog(SilentDialog):
    """Per-provider setup wizard & live diagnostic inspector backed by ConnectionManager."""

    def __init__(
        self,
        connections: ConnectionManager,
        provider_id: str,
        *,
        local_host: str = "127.0.0.1",
        local_port: int = 8000,
        mcp_path: str = "/mcp",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.connections = connections
        self.provider_id = provider_id
        self.provider = connections.get(provider_id)
        self._local_host = local_host
        self._local_port = local_port
        self._mcp_path = mcp_path

        self.setWindowTitle(f"Настройка транспорта: {provider_id}")
        self.setMinimumWidth(560)
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        det = self.provider.detect()
        det_text = f"{'✓ Найден' if det.installed else '✕ Не найден'}: {det.version or det.executable or det.detail}"
        self.det_label = QLabel(det_text)
        self.det_label.setWordWrap(True)
        self.det_label.setObjectName("Hint")
        root.addWidget(self.det_label)

        form = QFormLayout()
        form.setSpacing(6)
        cfg = self.provider.export_config()

        self.fields: dict[str, Any] = {}
        if provider_id == PROVIDER_NGROK:
            notice = QLabel(
                "Токен ngrok (ngrok Authtoken — отдельно от MCP Owner Token) сохраняется в SecretStore (DPAPI) "
                "и передаётся процессу через NGROK_AUTHTOKEN. ngrok CLI поддерживает только HTTP/HTTPS-прокси "
                "(SOCKS5 не поддерживается). Для стабильного OAuth рекомендуется закреплённый домен."
            )
            notice.setObjectName("Hint")
            notice.setWordWrap(True)
            root.addWidget(notice)

            tok_row = QHBoxLayout()
            tok_row.setSpacing(6)
            self.authtoken_edit = QLineEdit()
            self.authtoken_edit.setObjectName("UiInput")
            self.authtoken_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.authtoken_edit.setPlaceholderText(
                "Уже сохранён в SecretStore (оставьте пустым, чтобы не менять)"
                if self.provider.has_authtoken()  # type: ignore[attr-defined]
                else "Вставьте ngrok Authtoken с dashboard.ngrok.com"
            )
            self.authtoken_eye = QPushButton(tr("conn.token.show"))
            self.authtoken_eye.setObjectName("Ghost")
            self.authtoken_eye.clicked.connect(self._toggle_ngrok_eye)
            tok_row.addWidget(self.authtoken_edit, 1)
            tok_row.addWidget(self.authtoken_eye)

            self.domain_edit = QLineEdit(str(cfg.get("reserved_domain") or ""))
            self.domain_edit.setObjectName("UiInput")
            self.domain_edit.setPlaceholderText("mcp-example.ngrok-free.app или свой домен")
            self.api_edit = QLineEdit(str(cfg.get("local_api_url") or DEFAULT_NGROK_API_URL))
            self.api_edit.setObjectName("UiInput")
            self.bin_edit = QLineEdit(str(cfg.get("binary_path") or ""))
            self.bin_edit.setObjectName("UiInput")
            self.bin_edit.setPlaceholderText("Автопоиск ngrok.exe в PATH / LOCALAPPDATA")
            form.addRow("ngrok Authtoken (DPAPI)", tok_row)
            form.addRow("Домен (--url)", self.domain_edit)
            form.addRow("Local API URL", self.api_edit)
            form.addRow("Путь к ngrok", self.bin_edit)

        elif provider_id == PROVIDER_TAILSCALE:
            notice = QLabel(
                "Tailscale Funnel публикует выбранный путь в публичный интернет по HTTPS через MagicDNS. "
                "Разрешённые порты: 443, 8443, 10000. Системный демон Tailscale управляет собственным транспортом "
                "и не использует прокси-мост MCP-app. При остановке снимается только маршрут MCP-app."
            )
            notice.setObjectName("Hint")
            notice.setWordWrap(True)
            root.addWidget(notice)

            self.port_combo = SafeComboBox()
            for port in ALLOWED_FUNNEL_PORTS:
                self.port_combo.addItem(str(port), port)
            cur_port = int(cfg.get("https_port") or 443)
            self.port_combo.setCurrentIndex(max(0, self.port_combo.findData(cur_port)))

            self.host_edit = QLineEdit(str(cfg.get("hostname_override") or ""))
            self.host_edit.setObjectName("UiInput")
            self.host_edit.setPlaceholderText("Автоопределение через tailscale status --json")
            self.bin_edit = QLineEdit(str(cfg.get("binary_path") or ""))
            self.bin_edit.setObjectName("UiInput")
            self.bin_edit.setPlaceholderText("Автопоиск tailscale.exe")
            form.addRow("Публичный порт HTTPS", self.port_combo)
            form.addRow("DNS-имя (опционально)", self.host_edit)
            form.addRow("Путь к tailscale", self.bin_edit)

        root.addLayout(form)

        self.diag_output = QTextEdit()
        self.diag_output.setObjectName("ConsoleLog")
        self.diag_output.setReadOnly(True)
        self.diag_output.setMaximumHeight(130)
        self.diag_output.setPlaceholderText("Результаты проверки конфигурации появятся здесь.")
        root.addWidget(self.diag_output)

        buttons = QHBoxLayout()
        buttons.setSpacing(6)
        self.diag_btn = QPushButton("Проверить")
        self.diag_btn.setObjectName("Ghost")
        self.diag_btn.clicked.connect(self._run_diagnose)
        buttons.addWidget(self.diag_btn)

        buttons.addStretch(1)
        cancel_btn = QPushButton("Отмена")
        cancel_btn.setObjectName("Ghost")
        cancel_btn.clicked.connect(self.reject)
        self.save_btn = QPushButton("Сохранить")
        self.save_btn.setObjectName("Accent")
        self.save_btn.clicked.connect(self._save)
        buttons.addWidget(cancel_btn)
        buttons.addWidget(self.save_btn)
        root.addLayout(buttons)

    def _toggle_ngrok_eye(self) -> None:
        if not hasattr(self, "authtoken_edit"):
            return
        vis = self.authtoken_edit.echoMode() == QLineEdit.EchoMode.Password
        self.authtoken_edit.setEchoMode(QLineEdit.EchoMode.Normal if vis else QLineEdit.EchoMode.Password)
        self.authtoken_eye.setText(tr("conn.token.hide" if vis else "conn.token.show"))

    def _collect(self) -> tuple[dict[str, Any], dict[str, str] | None]:
        if self.provider_id == PROVIDER_NGROK:
            cfg = {
                "reserved_domain": self.domain_edit.text().strip(),
                "local_api_url": self.api_edit.text().strip() or DEFAULT_NGROK_API_URL,
                "binary_path": self.bin_edit.text().strip(),
            }
            tok = self.authtoken_edit.text().strip()
            secrets = {"authtoken": tok} if tok else None
            return cfg, secrets
        if self.provider_id == PROVIDER_TAILSCALE:
            cfg = {
                "https_port": int(self.port_combo.currentData()),
                "hostname_override": self.host_edit.text().strip(),
                "binary_path": self.bin_edit.text().strip(),
            }
            return cfg, None
        return {}, None

    def _apply_current(self) -> bool:
        cfg, secrets = self._collect()
        errors = self.connections.configure_provider(self.provider_id, cfg, secrets=secrets)
        if errors:
            SilentMessageBox.warning(self, "Ошибка параметров", "\n".join(errors))
            return False
        return True

    def _run_diagnose(self) -> None:
        if not self._apply_current():
            return
        checks = self.connections.diagnose_provider(
            self.provider_id,
            local_host=self._local_host,
            local_port=self._local_port,
            mcp_path=self._mcp_path,
        )
        self.diag_output.clear()
        for item in checks:
            mark = "✓" if item.ok else "✕"
            self.diag_output.append(f"{mark} {item.label}: {item.detail}")

    def _save(self) -> None:
        if not self._apply_current():
            return
        self.accept()
