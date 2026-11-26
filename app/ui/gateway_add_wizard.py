"""Automated multi-mode MCP Server onboarding wizard for MCP Gateway."""
from __future__ import annotations

import asyncio
import shlex
import webbrowser
from pathlib import Path
from urllib.parse import urlsplit

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.ui.components.cards import Badge, Divider, FlowLayout
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.safe_spin import SafeDoubleSpinBox
from app.ui.components.silent_dialog import SilentDialog, SilentMessageBox
from app.ui.i18n import LANG_EN, i18n, tr
from backend.gateway.client_configs import (
    DetectedClientSource,
    ParsedImportCandidate,
    detect_ai_client_configs,
    parse_config_file,
    parse_config_text,
)
from backend.gateway.discovery import (
    RemoteProbeResult,
    RuntimeCheckResult,
    build_profile_from_url_probe,
    inspect_stdio_runtime,
    probe_remote_mcp_url,
    probe_stdio_mcp_server,
    run_upstream_oauth_flow,
)
from backend.gateway.models import (
    AUTH_BEARER,
    AUTH_NONE,
    ISOLATION_PER_CLIENT,
    ISOLATION_SHARED,
    TRANSPORT_SSE,
    TRANSPORT_STDIO,
    TRANSPORT_STREAMABLE_HTTP,
    UpstreamServerProfile,
    normalize_server_id,
)
from backend.gateway.store import GatewayConfigStore
from backend.gateway.templates import (
    TEMPLATE_CATEGORIES,
    GatewayServerTemplate,
    list_templates,
)


class _ProbeWorker(QThread):
    finished_probe = pyqtSignal(object)

    def __init__(self, coro_fn, parent: QWidget | None = None) -> None:  # noqa: ANN001
        super().__init__(parent)
        self._coro_fn = coro_fn

    def run(self) -> None:
        try:
            res = asyncio.run(self._coro_fn())
        except Exception as exc:  # noqa: BLE001
            res = RemoteProbeResult(status="error", message=f"{type(exc).__name__}: {exc}")
        self.finished_probe.emit(res)


class AddMcpServerWizard(SilentDialog):
    """Unified guided flow: URL, JSON paste, File import, AI Client import, Verified template, or Manual."""

    MODE_URL = "url"
    MODE_JSON = "json"
    MODE_FILE = "file"
    MODE_CLIENT = "client"
    MODE_TEMPLATE = "template"
    MODE_MANUAL = "manual"

    def __init__(
        self,
        store: GatewayConfigStore,
        *,
        initial_mode: str = MODE_URL,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.store = store
        self.saved_server_ids: list[str] = []
        self.discovered_tools_by_server: dict[str, list[str]] = {}
        self._worker: _ProbeWorker | None = None
        self._last_url_probe: RemoteProbeResult | None = None
        self._last_oauth_ref: str = ""
        self._detected_sources: list[DetectedClientSource] = []
        self._parsed_candidates: list[ParsedImportCandidate] = []
        self._template_field_widgets: dict[str, QLineEdit] = {}
        self._active_template: GatewayServerTemplate | None = None

        self.setWindowTitle(tr("gateway.wizard.title"))
        self.setMinimumSize(640, 520)
        self.resize(700, 580)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        self._lead_lbl = QLabel(tr("gateway.wizard.lead"))
        self._lead_lbl.setObjectName("Hint")
        self._lead_lbl.setWordWrap(True)
        root.addWidget(self._lead_lbl)

        # Mode pills
        mode_flow = FlowLayout(spacing=6)
        self._mode_buttons: dict[str, QPushButton] = {}
        modes = (
            (self.MODE_URL, tr("gateway.wizard.mode.url")),
            (self.MODE_JSON, tr("gateway.wizard.mode.json")),
            (self.MODE_FILE, tr("gateway.wizard.mode.file")),
            (self.MODE_CLIENT, tr("gateway.wizard.mode.client")),
            (self.MODE_TEMPLATE, tr("gateway.wizard.mode.template")),
            (self.MODE_MANUAL, tr("gateway.wizard.mode.manual")),
        )
        for m_id, m_label in modes:
            btn = QPushButton(m_label)
            btn.setObjectName("FilterPill")
            btn.setCheckable(True)
            btn.clicked.connect(lambda _c=False, mode=m_id: self.set_mode(mode))
            self._mode_buttons[m_id] = btn
            mode_flow.addWidget(btn)
        root.addLayout(mode_flow)
        root.addWidget(Divider())

        self.preview_box = QPlainTextEdit()
        self.preview_box.setObjectName("ConsoleLog")
        self.preview_box.setReadOnly(True)
        self.preview_box.setMaximumHeight(110)
        self.preview_box.setPlaceholderText(tr("gateway.wizard.preview_placeholder"))

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_url_page())       # 0
        self.stack.addWidget(self._build_json_page())      # 1
        self.stack.addWidget(self._build_file_page())      # 2
        self.stack.addWidget(self._build_client_page())    # 3
        self.stack.addWidget(self._build_template_page())  # 4
        self.stack.addWidget(self._build_manual_page())    # 5
        root.addWidget(self.stack, 1)

        # Shared verification + owner security approval box
        root.addWidget(Divider())
        root.addWidget(self.preview_box)

        sec_row = QHBoxLayout()
        sec_row.setSpacing(8)
        self.approve_chk = QCheckBox(tr("gateway.wizard.approve_chk"))
        self.approve_chk.setChecked(True)
        self.profile_badge = Badge(tr("clients.role.allowlist"), variant="info")
        sec_row.addWidget(self.approve_chk, 1)
        sec_row.addWidget(self.profile_badge, 0)
        root.addLayout(sec_row)

        footer = QHBoxLayout()
        footer.setSpacing(8)
        self.verify_btn = QPushButton(tr("gateway.wizard.btn.verify"))
        self.verify_btn.clicked.connect(self._verify_current)
        self.oauth_btn = QPushButton(tr("gateway.wizard.btn.oauth"))
        self.oauth_btn.clicked.connect(self._run_url_oauth)
        self.oauth_btn.hide()
        self.cancel_btn = QPushButton(tr("common.cancel"))
        self.cancel_btn.setObjectName("Ghost")
        self.cancel_btn.clicked.connect(self.reject)
        self.connect_btn = QPushButton(tr("gateway.wizard.btn.connect"))
        self.connect_btn.setObjectName("Accent")
        self.connect_btn.clicked.connect(self._connect_and_save)

        footer.addWidget(self.verify_btn)
        footer.addWidget(self.oauth_btn)
        footer.addStretch(1)
        footer.addWidget(self.cancel_btn)
        footer.addWidget(self.connect_btn)
        root.addLayout(footer)

        self.set_mode(initial_mode if initial_mode in self._mode_buttons else self.MODE_URL)

    # ------------------------------------------------------------------ pages
    def _build_url_page(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 0, 0)
        form = QFormLayout()
        form.setSpacing(8)
        self.url_edit = QLineEdit()
        self.url_edit.setObjectName("UiInput")
        self.url_edit.setPlaceholderText("https://mcp.example.com/mcp")
        self.url_name_edit = QLineEdit()
        self.url_name_edit.setObjectName("UiInput")
        self.url_name_edit.setPlaceholderText(tr("gateway.wizard.optional_auto"))
        self.url_bearer_edit = QLineEdit()
        self.url_bearer_edit.setObjectName("UiInput")
        self.url_bearer_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.url_bearer_edit.setPlaceholderText(tr("gateway.wizard.bearer_optional"))
        self.url_local_chk = QCheckBox(tr("gateway.dlg.allow_local"))
        form.addRow(tr("gateway.dlg.url"), self.url_edit)
        form.addRow(tr("gateway.dlg.name"), self.url_name_edit)
        form.addRow(tr("gateway.dlg.bearer_token"), self.url_bearer_edit)
        form.addRow("", self.url_local_chk)
        lay.addLayout(form)
        lay.addStretch(1)
        return w

    def _build_json_page(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 0, 0)
        lay.setSpacing(6)
        hint = QLabel(tr("gateway.wizard.json_hint"))
        hint.setObjectName("Hint")
        hint.setWordWrap(True)
        lay.addWidget(hint)
        self.json_edit = QPlainTextEdit()
        self.json_edit.setObjectName("ConsoleLog")
        self.json_edit.setPlaceholderText('{\n  "mcpServers": {\n    "my-server": {\n      "url": "https://..."\n    }\n  }\n}')
        lay.addWidget(self.json_edit, 1)
        self.json_candidates_list = QListWidget()
        self.json_candidates_list.setMaximumHeight(95)
        lay.addWidget(self.json_candidates_list)
        return w

    def _build_file_page(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 0, 0)
        lay.setSpacing(8)
        row = QHBoxLayout()
        row.setSpacing(6)
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setObjectName("UiInput")
        self.file_path_edit.setPlaceholderText("claude_desktop_config.json / mcp.json / config.toml")
        browse_btn = QPushButton(tr("gateway.import.load_file"))
        browse_btn.clicked.connect(self._browse_config_file)
        row.addWidget(self.file_path_edit, 1)
        row.addWidget(browse_btn)
        lay.addLayout(row)
        self.file_candidates_list = QListWidget()
        lay.addWidget(self.file_candidates_list, 1)
        return w

    def _build_client_page(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 0, 0)
        lay.setSpacing(8)
        top = QHBoxLayout()
        self.client_combo = SafeComboBox()
        self.client_combo.currentIndexChanged.connect(self._on_client_source_changed)
        rescan_btn = QPushButton(tr("clients.refresh"))
        rescan_btn.setObjectName("Ghost")
        rescan_btn.clicked.connect(self._scan_ai_clients)
        top.addWidget(self.client_combo, 1)
        top.addWidget(rescan_btn)
        lay.addLayout(top)
        self.client_note_lbl = QLabel("")
        self.client_note_lbl.setObjectName("Hint")
        self.client_note_lbl.setWordWrap(True)
        lay.addWidget(self.client_note_lbl)
        self.client_candidates_list = QListWidget()
        lay.addWidget(self.client_candidates_list, 1)
        return w

    def _build_template_page(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 0, 0)
        lay.setSpacing(8)
        selectors = QHBoxLayout()
        selectors.setSpacing(8)
        self.tpl_category_combo = SafeComboBox()
        is_en = i18n.language == LANG_EN
        for cat_id, ru_lbl, en_lbl in TEMPLATE_CATEGORIES:
            self.tpl_category_combo.addItem(en_lbl if is_en else ru_lbl, cat_id)
        self.tpl_category_combo.currentIndexChanged.connect(self._populate_templates_for_category)

        self.tpl_combo = SafeComboBox()
        self.tpl_combo.currentIndexChanged.connect(self._on_template_selected)
        selectors.addWidget(self.tpl_category_combo, 1)
        selectors.addWidget(self.tpl_combo, 2)
        lay.addLayout(selectors)

        self.tpl_desc_lbl = QLabel("")
        self.tpl_desc_lbl.setObjectName("Hint")
        self.tpl_desc_lbl.setWordWrap(True)
        lay.addWidget(self.tpl_desc_lbl)

        self.tpl_fields_host = QWidget()
        self.tpl_fields_form = QFormLayout(self.tpl_fields_host)
        self.tpl_fields_form.setContentsMargins(0, 4, 0, 4)
        self.tpl_fields_form.setSpacing(8)
        lay.addWidget(self.tpl_fields_host)
        lay.addStretch(1)
        self._populate_templates_for_category()
        return w

    def _build_manual_page(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 0, 0)
        form = QFormLayout()
        form.setSpacing(8)
        self.man_id_edit = QLineEdit()
        self.man_id_edit.setObjectName("UiInput")
        self.man_name_edit = QLineEdit()
        self.man_name_edit.setObjectName("UiInput")
        self.man_transport_combo = SafeComboBox()
        for tid in (TRANSPORT_STDIO, TRANSPORT_STREAMABLE_HTTP, TRANSPORT_SSE):
            self.man_transport_combo.addItem(tid, tid)
        self.man_cmd_edit = QLineEdit()
        self.man_cmd_edit.setObjectName("UiInput")
        self.man_cmd_edit.setPlaceholderText("python / npx / uvx / C:\\path\\server.exe")
        self.man_args_edit = QLineEdit()
        self.man_args_edit.setObjectName("UiInput")
        self.man_cwd_edit = QLineEdit()
        self.man_cwd_edit.setObjectName("UiInput")
        self.man_url_edit = QLineEdit()
        self.man_url_edit.setObjectName("UiInput")
        self.man_bearer_edit = QLineEdit()
        self.man_bearer_edit.setObjectName("UiInput")
        self.man_bearer_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.man_timeout_spin = SafeDoubleSpinBox()
        self.man_timeout_spin.setRange(1.0, 600.0)
        self.man_timeout_spin.setValue(30.0)
        self.man_isolation_combo = SafeComboBox()
        self.man_isolation_combo.addItem(tr(f"gateway.isolation.{ISOLATION_PER_CLIENT}"), ISOLATION_PER_CLIENT)
        self.man_isolation_combo.addItem(tr(f"gateway.isolation.{ISOLATION_SHARED}"), ISOLATION_SHARED)

        form.addRow(tr("gateway.dlg.id"), self.man_id_edit)
        form.addRow(tr("gateway.dlg.name"), self.man_name_edit)
        form.addRow(tr("gateway.dlg.transport"), self.man_transport_combo)
        form.addRow(tr("gateway.dlg.command"), self.man_cmd_edit)
        form.addRow(tr("gateway.dlg.args"), self.man_args_edit)
        form.addRow(tr("gateway.dlg.cwd"), self.man_cwd_edit)
        form.addRow(tr("gateway.dlg.url"), self.man_url_edit)
        form.addRow(tr("gateway.dlg.bearer_token"), self.man_bearer_edit)
        form.addRow(tr("gateway.dlg.timeout"), self.man_timeout_spin)
        form.addRow(tr("gateway.dlg.isolation"), self.man_isolation_combo)
        lay.addLayout(form)
        self.man_transport_combo.currentIndexChanged.connect(self._sync_manual_fields)
        self._sync_manual_fields()
        return w

    def _sync_manual_fields(self) -> None:
        is_stdio = self.man_transport_combo.currentData() == TRANSPORT_STDIO
        for widget in (self.man_cmd_edit, self.man_args_edit, self.man_cwd_edit):
            widget.setEnabled(is_stdio)
        for widget in (self.man_url_edit, self.man_bearer_edit):
            widget.setEnabled(not is_stdio)

    def set_mode(self, mode: str) -> None:
        self._current_mode = mode
        idx_map = {
            self.MODE_URL: 0,
            self.MODE_JSON: 1,
            self.MODE_FILE: 2,
            self.MODE_CLIENT: 3,
            self.MODE_TEMPLATE: 4,
            self.MODE_MANUAL: 5,
        }
        for key, btn in self._mode_buttons.items():
            btn.setChecked(key == mode)
        self.stack.setCurrentIndex(idx_map.get(mode, 0))
        self.oauth_btn.hide()
        self.preview_box.clear()
        if mode == self.MODE_CLIENT and self.client_combo.count() == 0:
            self._scan_ai_clients()
        if mode == self.MODE_TEMPLATE:
            self._render_template_preview()

    # ------------------------------------------------------------------ candidate helpers
    def _populate_candidate_list(self, lst: QListWidget, candidates: list[ParsedImportCandidate]) -> None:
        lst.clear()
        self._parsed_candidates = candidates
        for cand in candidates:
            p = cand.profile
            target = f"{p.command} {' '.join(p.args)}".strip() if p.transport == TRANSPORT_STDIO else p.url
            dup_tag = f" [duplicate: {cand.duplicate_of}]" if cand.duplicate_of else ""
            item = QListWidgetItem(f"{p.name} ({p.transport}) — {target}{dup_tag}")
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked if cand.duplicate_of else Qt.CheckState.Checked)
            item.setData(Qt.ItemDataRole.UserRole, cand)
            lst.addItem(item)
        self._update_candidates_preview(candidates)

    def _update_candidates_preview(self, candidates: list[ParsedImportCandidate]) -> None:
        lines: list[str] = []
        for cand in candidates:
            p = cand.profile
            cmd_or_url = f"{p.command} {' '.join(p.args)}".strip() if p.transport == TRANSPORT_STDIO else p.url
            lines.append(f"[{p.server_id}] {p.name} ({p.transport}) -> {cmd_or_url}")
            if p.transport == TRANSPORT_STDIO and p.command:
                rt = inspect_stdio_runtime(p.command, p.args, p.cwd)
                lines.append(f"  runtime: {'OK (' + rt.resolved_executable + ')' if rt.ok else rt.error_message}")
                if not rt.ok:
                    hint = rt.install_hint_en if i18n.language == LANG_EN else rt.install_hint_ru
                    if hint:
                        lines.append(f"  install: {hint}")
            if cand.secret_env or cand.bearer_token or cand.secret_headers:
                lines.append("  secrets -> SecretStore (DPAPI)")
            for w in cand.warnings:
                lines.append(f"  ! {w}")
        self.preview_box.setPlainText("\n".join(lines) if lines else tr("gateway.import.no_servers"))

    def _browse_config_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            tr("gateway.import.load_file"),
            "",
            "MCP Config (*.json *.toml);;All Files (*)",
        )
        if not path:
            return
        self.file_path_edit.setText(path)
        self._load_file_candidates()

    def _load_file_candidates(self) -> None:
        p = Path(self.file_path_edit.text().strip())
        if not p.is_file():
            self.preview_box.setPlainText(tr("gateway.wizard.file_missing"))
            return
        try:
            cands = parse_config_file(p, store=self.store, source_name=p.name)
            self._populate_candidate_list(self.file_candidates_list, cands)
        except Exception as exc:  # noqa: BLE001
            self.preview_box.setPlainText(str(exc))

    def _scan_ai_clients(self) -> None:
        self._detected_sources = detect_ai_client_configs()
        self.client_combo.blockSignals(True)
        self.client_combo.clear()
        is_en = i18n.language == LANG_EN
        for src in self._detected_sources:
            name = src.display_name_en if is_en else src.display_name_ru
            badge = " [✓]" if src.exists else ""
            self.client_combo.addItem(f"{name}{badge}", src.client_key)
        self.client_combo.blockSignals(False)
        self._on_client_source_changed()

    def _on_client_source_changed(self) -> None:
        idx = self.client_combo.currentIndex()
        if idx < 0 or idx >= len(self._detected_sources):
            return
        src = self._detected_sources[idx]
        is_en = i18n.language == LANG_EN
        note = src.note_en if is_en else src.note_ru
        if src.config_path is not None:
            note = f"{note}\n{src.config_path}"
        self.client_note_lbl.setText(note)
        self.client_candidates_list.clear()
        self._parsed_candidates = []
        if not src.exists or src.config_path is None:
            self.preview_box.setPlainText(tr("gateway.wizard.client_no_file"))
            return
        try:
            cands = parse_config_file(
                src.config_path,
                store=self.store,
                source_name=src.display_name_en,
            )
            self._populate_candidate_list(self.client_candidates_list, cands)
        except Exception as exc:  # noqa: BLE001
            self.preview_box.setPlainText(str(exc))

    def _populate_templates_for_category(self) -> None:
        cat = str(self.tpl_category_combo.currentData() or "filesystem")
        is_en = i18n.language == LANG_EN
        self.tpl_combo.blockSignals(True)
        self.tpl_combo.clear()
        for tpl in list_templates(cat):
            self.tpl_combo.addItem(tpl.title_en if is_en else tpl.title_ru, tpl.template_id)
        self.tpl_combo.blockSignals(False)
        self._on_template_selected()

    def _on_template_selected(self) -> None:
        tid = str(self.tpl_combo.currentData() or "")
        tpl = next((t for t in list_templates() if t.template_id == tid), None)
        self._active_template = tpl
        while self.tpl_fields_form.rowCount() > 0:
            self.tpl_fields_form.removeRow(0)
        self._template_field_widgets.clear()
        if tpl is None:
            return
        is_en = i18n.language == LANG_EN
        self.tpl_desc_lbl.setText(tpl.description_en if is_en else tpl.description_ru)
        for fld in tpl.fields:
            edit = QLineEdit(fld.default)
            edit.setObjectName("UiInput")
            edit.setPlaceholderText(fld.placeholder)
            if fld.secret:
                edit.setEchoMode(QLineEdit.EchoMode.Password)
            edit.textChanged.connect(lambda *_: self._render_template_preview())
            self._template_field_widgets[fld.key] = edit
            self.tpl_fields_form.addRow(fld.label_en if is_en else fld.label_ru, edit)
        self._render_template_preview()

    def _render_template_preview(self) -> None:
        tpl = self._active_template
        if tpl is None:
            return
        is_en = i18n.language == LANG_EN
        vals = {k: w.text().strip() for k, w in self._template_field_widgets.items()}
        prof, _sec, _tok = tpl.build_profile(values=vals)
        lines = [
            f"ID: {prof.server_id} | transport: {prof.transport} | profile: allowlist",
            f"source: {tpl.package_source or tpl.url}",
        ]
        if prof.transport == TRANSPORT_STDIO:
            lines.append(f"command: {prof.command} {' '.join(prof.args)}".strip())
            rt: RuntimeCheckResult = inspect_stdio_runtime(prof.command, prof.args, prof.cwd)
            lines.append(f"runtime: {'OK (' + rt.resolved_executable + ')' if rt.ok else rt.error_message}")
            if not rt.ok:
                hint = rt.install_hint_en if is_en else rt.install_hint_ru
                if hint:
                    lines.append(f"install: {hint}")
        else:
            lines.append(f"url: {prof.url}")
        note = tpl.notes_en if is_en else tpl.notes_ru
        if note:
            lines.append(f"note: {note}")
        self.preview_box.setPlainText("\n".join(lines))

    # ------------------------------------------------------------------ verification & save
    def _verify_current(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        mode = self._current_mode
        if mode == self.MODE_URL:
            url = self.url_edit.text().strip()
            bearer = self.url_bearer_edit.text().strip()
            allow_local = self.url_local_chk.isChecked() or url.startswith(("http://127.0.0.1", "http://localhost"))
            self.preview_box.setPlainText(tr("gateway.wizard.probing"))
            self.verify_btn.setEnabled(False)
            self._worker = _ProbeWorker(
                lambda: probe_remote_mcp_url(
                    url, bearer_token=bearer, allow_local_endpoint=allow_local, timeout=10.0
                ),
                self,
            )
            self._worker.finished_probe.connect(self._on_url_probe_done)
            self._worker.start()
            return
        if mode == self.MODE_JSON:
            try:
                cands = parse_config_text(self.json_edit.toPlainText(), source_name="json_paste", store=self.store)
                self._populate_candidate_list(self.json_candidates_list, cands)
            except Exception as exc:  # noqa: BLE001
                self.preview_box.setPlainText(str(exc))
            return
        if mode == self.MODE_FILE:
            self._load_file_candidates()
            return
        if mode == self.MODE_CLIENT:
            self._on_client_source_changed()
            return
        if mode == self.MODE_TEMPLATE and self._active_template is not None:
            vals = {k: w.text().strip() for k, w in self._template_field_widgets.items()}
            prof, sec_env, bearer = self._active_template.build_profile(values=vals)
            self._probe_profile(prof, sec_env=sec_env, bearer=bearer or "")
            return
        if mode == self.MODE_MANUAL:
            prof, bearer = self._build_manual_profile()
            self._probe_profile(prof, bearer=bearer)

    def _probe_profile(self, prof: UpstreamServerProfile, *, sec_env: dict[str, str] | None = None, bearer: str = "") -> None:
        self.preview_box.setPlainText(tr("gateway.wizard.probing"))
        self.verify_btn.setEnabled(False)
        if prof.transport == TRANSPORT_STDIO:
            env = {**prof.env, **(sec_env or {})}
            self._worker = _ProbeWorker(
                lambda: probe_stdio_mcp_server(prof.command, prof.args, cwd=prof.cwd, env=env, timeout=12.0),
                self,
            )
        else:
            self._worker = _ProbeWorker(
                lambda: probe_remote_mcp_url(
                    prof.url,
                    bearer_token=bearer,
                    allow_local_endpoint=prof.allow_local_endpoint,
                    timeout=10.0,
                ),
                self,
            )
        self._worker.finished_probe.connect(self._on_generic_probe_done)
        self._worker.start()

    def _on_url_probe_done(self, result: object) -> None:
        self.verify_btn.setEnabled(True)
        if not isinstance(result, RemoteProbeResult):
            return
        self._last_url_probe = result
        if result.status == "ok":
            self.oauth_btn.hide()
            if result.server_name and not self.url_name_edit.text().strip():
                self.url_name_edit.setText(result.server_name)
            self.preview_box.setPlainText(
                f"status: OK | transport: {result.transport} | server: {result.server_name or '-'} {result.server_version}\n"
                f"tools ({len(result.tools)}): {', '.join(result.tools[:15]) or 'none'}"
            )
        elif result.status == "auth_required":
            self.oauth_btn.setVisible(result.auth_kind == "oauth")
            self.preview_box.setPlainText(
                f"status: AUTH REQUIRED ({result.auth_kind})\n{result.message}\n"
                + (f"OAuth issuer: {result.oauth_issuer}" if result.oauth_issuer else "")
            )
        else:
            self.oauth_btn.hide()
            self.preview_box.setPlainText(f"status: ERROR\n{result.message}")

    def _on_generic_probe_done(self, result: object) -> None:
        self.verify_btn.setEnabled(True)
        if not isinstance(result, RemoteProbeResult):
            return
        if result.status == "ok":
            self.preview_box.setPlainText(
                f"status: OK | transport: {result.transport} | server: {result.server_name or '-'}\n"
                f"tools ({len(result.tools)}): {', '.join(result.tools[:15]) or 'none'}"
            )
        else:
            self.preview_box.setPlainText(f"status: {result.status.upper()}\n{result.message}")

    def _run_url_oauth(self) -> None:
        url = self.url_edit.text().strip()
        if not url:
            return
        sid = normalize_server_id(self.url_name_edit.text().strip() or urlsplit(url).hostname or "remote")
        allow_local = self.url_local_chk.isChecked() or url.startswith(("http://127.0.0.1", "http://localhost"))
        self.oauth_btn.setEnabled(False)
        self.preview_box.setPlainText(tr("gateway.wizard.oauth_waiting"))

        async def _flow():
            res, ref = await run_upstream_oauth_flow(
                url,
                server_id=sid,
                secret_store=self.store.secrets,
                open_browser_fn=webbrowser.open,
                allow_local_endpoint=allow_local,
            )
            return res, ref

        def _done(pair: object) -> None:
            self.oauth_btn.setEnabled(True)
            if isinstance(pair, tuple) and len(pair) == 2:
                res, ref = pair
                self._last_oauth_ref = str(ref)
                self._on_url_probe_done(res)

        worker = QThread(self)
        self._oauth_worker = worker  # keep reference alive

        class _Runner(QThread):
            done = pyqtSignal(object)

            def run(self_inner) -> None:  # noqa: N805
                try:
                    out = asyncio.run(_flow())
                except Exception as exc:  # noqa: BLE001
                    out = (RemoteProbeResult(status="error", message=str(exc)), "")
                self_inner.done.emit(out)

        rw = _Runner(self)
        self._oauth_worker = rw
        rw.done.connect(_done)
        rw.start()

    def _build_manual_profile(self) -> tuple[UpstreamServerProfile, str]:
        raw_args = self.man_args_edit.text().strip()
        try:
            args = tuple(shlex.split(raw_args, posix=False)) if raw_args else ()
        except ValueError:
            args = tuple(raw_args.split())
        url = self.man_url_edit.text().strip()
        bearer = self.man_bearer_edit.text().strip()
        sid = normalize_server_id(self.man_id_edit.text().strip() or self.man_name_edit.text().strip() or "custom")
        prof = UpstreamServerProfile(
            server_id=sid,
            name=(self.man_name_edit.text().strip() or sid),
            transport=str(self.man_transport_combo.currentData() or TRANSPORT_STDIO),
            enabled=True,
            autostart=False,
            command=self.man_cmd_edit.text().strip(),
            args=args,
            cwd=self.man_cwd_edit.text().strip(),
            url=url,
            auth_mode=AUTH_BEARER if bearer else AUTH_NONE,
            allow_local_endpoint=url.startswith(("http://127.0.0.1", "http://localhost")),
            session_isolation=str(self.man_isolation_combo.currentData() or ISOLATION_PER_CLIENT),
            min_profile="allowlist",
            timeout_seconds=float(self.man_timeout_spin.value()),
            approved_by_owner=True,
        )
        return prof, bearer

    def _connect_and_save(self) -> None:
        if not self.approve_chk.isChecked():
            SilentMessageBox.warning(self, self.windowTitle(), tr("gateway.wizard.need_approval"))
            return

        mode = self._current_mode
        saved: list[str] = []

        if mode == self.MODE_URL:
            url = self.url_edit.text().strip()
            if not url:
                SilentMessageBox.warning(self, self.windowTitle(), tr("gateway.wizard.need_url"))
                return
            probe = self._last_url_probe or RemoteProbeResult(status="ok", transport=TRANSPORT_STREAMABLE_HTTP)
            bearer = self.url_bearer_edit.text().strip() or None
            auth_mode = AUTH_BEARER if (bearer or self._last_oauth_ref) else AUTH_NONE
            prof = build_profile_from_url_probe(
                url,
                probe,
                name=self.url_name_edit.text().strip() or None,
                auth_mode=auth_mode,
                auth_secret_ref=self._last_oauth_ref,
                allow_local_endpoint=self.url_local_chk.isChecked(),
            )
            errs = self.store.upsert(prof, bearer_token=bearer)
            if errs:
                SilentMessageBox.warning(self, self.windowTitle(), "\n".join(errs))
                return
            saved.append(prof.server_id)

        elif mode in (self.MODE_JSON, self.MODE_FILE, self.MODE_CLIENT):
            list_widget = {
                self.MODE_JSON: self.json_candidates_list,
                self.MODE_FILE: self.file_candidates_list,
                self.MODE_CLIENT: self.client_candidates_list,
            }[mode]
            if list_widget.count() == 0:
                self._verify_current()
            selected: list[ParsedImportCandidate] = []
            for row in range(list_widget.count()):
                it = list_widget.item(row)
                if it is not None and it.checkState() == Qt.CheckState.Checked:
                    cand = it.data(Qt.ItemDataRole.UserRole)
                    if isinstance(cand, ParsedImportCandidate):
                        selected.append(cand)
            if not selected:
                SilentMessageBox.warning(self, self.windowTitle(), tr("gateway.import.no_servers"))
                return
            for cand in selected:
                prof = UpstreamServerProfile.from_dict(
                    {
                        **cand.profile.to_dict(),
                        "enabled": True,
                        "approved_by_owner": True,
                        "min_profile": "allowlist",
                    }
                )
                errs = self.store.upsert(
                    prof,
                    secret_env=cand.secret_env or None,
                    bearer_token=cand.bearer_token,
                    secret_headers=cand.secret_headers or None,
                )
                if errs:
                    SilentMessageBox.warning(self, self.windowTitle(), "\n".join(errs))
                    return
                saved.append(prof.server_id)

        elif mode == self.MODE_TEMPLATE and self._active_template is not None:
            vals = {k: w.text().strip() for k, w in self._template_field_widgets.items()}
            prof, sec_env, bearer = self._active_template.build_profile(values=vals)
            errs = self.store.upsert(prof, secret_env=sec_env or None, bearer_token=bearer)
            if errs:
                SilentMessageBox.warning(self, self.windowTitle(), "\n".join(errs))
                return
            saved.append(prof.server_id)

        elif mode == self.MODE_MANUAL:
            prof, bearer = self._build_manual_profile()
            errs = self.store.upsert(prof, bearer_token=bearer or None)
            if errs:
                SilentMessageBox.warning(self, self.windowTitle(), "\n".join(errs))
                return
            saved.append(prof.server_id)

        self.saved_server_ids = saved
        self.accept()
