"""Compact 4-step static read-only Workspace addition wizard (Stage N04)."""
from __future__ import annotations

import json
import shlex
import threading
from dataclasses import dataclass

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
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.ui.components.cards import Badge, Divider, FlowLayout
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.silent_dialog import SilentDialog, SilentMessageBox
from app.ui.i18n import tr
from backend.servers.models import ServerProfile
from backend.servers.store import ServerConfigStore
from backend.servers.templates import build_profile_from_template
from backend.workspaces.discovery import (
    CommandProposal,
    DiagnosticItem,
    DiscoveryLimits,
    ServerProposal,
    SubprojectCandidate,
    WizardAdditionPreview,
    WorkspaceDiscoveryResult,
    analyze_workspace_directory,
    discover_projects_in_directory,
    redact_discovery_text,
    suggest_unique_workspace_id,
)
from backend.workspaces.models import (
    WORKSPACE_MIN_PROFILES,
    WorkspacePermissions,
    WorkspaceProfile,
)
from backend.workspaces.server_links import WorkspaceServerCoordinator
from backend.workspaces.store import WorkspaceStore


@dataclass
class _CommandRowWidgets:
    container: QWidget
    enable_cb: QCheckBox
    name_edit: QLineEdit
    cmd_edit: QLineEdit
    source_lbl: QLabel


@dataclass
class _ServerRowWidgets:
    enable_cb: QCheckBox
    name_edit: QLineEdit
    proposal: ServerProposal


class _DiscoveryWorker(QThread):
    finished_discovery = pyqtSignal(int, str, object, str, arguments=["generation", "kind", "payload", "error"])

    def __init__(
        self,
        *,
        generation: int,
        mode: str,
        target_path: str,
        scan_depth: int,
        cancel_event: threading.Event,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._generation = generation
        self._mode = mode
        self._target_path = target_path
        self._scan_depth = scan_depth
        self._cancel_event = cancel_event

    def run(self) -> None:
        try:
            limits = DiscoveryLimits()
            if self._mode == "scan":
                scan_diags: list[DiagnosticItem] = []
                items = discover_projects_in_directory(
                    self._target_path,
                    max_depth=self._scan_depth,
                    limits=limits,
                    cancel_event=self._cancel_event,
                    diagnostics_out=scan_diags,
                )
                self.finished_discovery.emit(self._generation, "scan", (items, scan_diags), "")
            else:
                res = analyze_workspace_directory(
                    self._target_path,
                    limits=limits,
                    cancel_event=self._cancel_event,
                )
                self.finished_discovery.emit(self._generation, "single", res, "")
        except Exception as exc:  # noqa: BLE001
            self.finished_discovery.emit(
                self._generation,
                self._mode,
                None,
                redact_discovery_text(str(exc)) or type(exc).__name__,
            )


def _split_csv(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _safe_scroll_wrap(widget: QWidget) -> QScrollArea:
    area = QScrollArea()
    area.setObjectName("Page")
    area.setWidgetResizable(True)
    area.setFrameShape(QScrollArea.Shape.NoFrame)
    area.setWidget(widget)
    return area


class WorkspaceWizardDialog(SilentDialog):
    """Four-step bounded read-only project discovery and Workspace creation wizard."""

    def __init__(
        self,
        workspace_store: WorkspaceStore,
        server_store: ServerConfigStore,
        coordinator: WorkspaceServerCoordinator,
        *,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._ws_store = workspace_store
        self._srv_store = server_store
        self._coordinator = coordinator

        self.committed_workspace_id: str | None = None
        self.committed_server_names: tuple[str, ...] = ()
        self.manual_requested: bool = False

        self._generation = 0
        self._worker: _DiscoveryWorker | None = None
        self._retired_workers: list[_DiscoveryWorker] = []
        self._analyzing = False
        self._cancel_event: threading.Event | None = None
        self._committing = False
        self._discovery: WorkspaceDiscoveryResult | None = None
        self._scan_candidates: list[SubprojectCandidate] = []
        self._last_preview: WizardAdditionPreview | None = None
        self._cmd_rows: list[_CommandRowWidgets] = []
        self._srv_rows: list[_ServerRowWidgets] = []
        self._link_checks: dict[str, QCheckBox] = {}
        self._mode = "single"

        self.setMinimumSize(620, 460)
        self.resize(740, 540)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        self._lead_lbl = QLabel()
        self._lead_lbl.setObjectName("Hint")
        self._lead_lbl.setWordWrap(True)
        root.addWidget(self._lead_lbl)

        step_bar = FlowLayout(spacing=6)
        self._step_pills: list[Badge] = []
        for _idx in range(4):
            pill = Badge("", variant="neutral")
            self._step_pills.append(pill)
            step_bar.addWidget(pill)
        root.addLayout(step_bar)
        root.addWidget(Divider())

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_step_source())
        self.stack.addWidget(self._build_step_analysis())
        self.stack.addWidget(_safe_scroll_wrap(self._build_step_proposals()))
        self.stack.addWidget(_safe_scroll_wrap(self._build_step_access()))
        root.addWidget(self.stack, 1)

        root.addWidget(Divider())
        footer = QHBoxLayout()
        footer.setSpacing(8)
        self.manual_btn = QPushButton()
        self.manual_btn.setObjectName("Ghost")
        self.manual_btn.clicked.connect(self._request_manual_form)
        self.back_btn = QPushButton()
        self.back_btn.clicked.connect(self.go_back)
        self.cancel_btn = QPushButton()
        self.cancel_btn.setObjectName("Ghost")
        self.cancel_btn.clicked.connect(self.reject)
        self.next_btn = QPushButton()
        self.next_btn.setObjectName("Accent")
        self.next_btn.clicked.connect(self._on_primary_clicked)

        footer.addWidget(self.manual_btn)
        footer.addStretch(1)
        footer.addWidget(self.back_btn)
        footer.addWidget(self.cancel_btn)
        footer.addWidget(self.next_btn)
        root.addLayout(footer)

        self.retranslate()
        self._set_step(0)

    def _build_step_source(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 0, 0)
        lay.setSpacing(10)

        mode_row = FlowLayout(spacing=6)
        self.mode_single_btn = QPushButton()
        self.mode_single_btn.setObjectName("FilterPill")
        self.mode_single_btn.setCheckable(True)
        self.mode_single_btn.setChecked(True)
        self.mode_single_btn.clicked.connect(lambda: self._set_mode("single"))

        self.mode_scan_btn = QPushButton()
        self.mode_scan_btn.setObjectName("FilterPill")
        self.mode_scan_btn.setCheckable(True)
        self.mode_scan_btn.clicked.connect(lambda: self._set_mode("scan"))

        mode_row.addWidget(self.mode_single_btn)
        mode_row.addWidget(self.mode_scan_btn)
        lay.addLayout(mode_row)

        form = QFormLayout()
        form.setSpacing(8)
        path_row = QHBoxLayout()
        path_row.setSpacing(6)
        self.path_edit = QLineEdit()
        self.path_edit.setObjectName("UiInput")
        self.path_edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.path_edit.textChanged.connect(self._invalidate_discovery)
        self.browse_btn = QPushButton()
        self.browse_btn.clicked.connect(self._browse_dir)
        path_row.addWidget(self.path_edit, 1)
        path_row.addWidget(self.browse_btn)
        self._path_form_lbl = QLabel()
        form.addRow(self._path_form_lbl, path_row)

        self.scan_depth_combo = SafeComboBox()
        self.scan_depth_combo.addItem("1", 1)
        self.scan_depth_combo.addItem("2", 2)
        self.scan_depth_combo.setCurrentIndex(1)
        self._depth_form_lbl = QLabel()
        form.addRow(self._depth_form_lbl, self.scan_depth_combo)
        lay.addLayout(form)

        self._readonly_note_lbl = QLabel()
        self._readonly_note_lbl.setObjectName("Hint")
        self._readonly_note_lbl.setWordWrap(True)
        lay.addWidget(self._readonly_note_lbl)
        lay.addStretch(1)
        self._update_mode_controls()
        return w

    def _build_step_analysis(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 0, 0)
        lay.setSpacing(8)

        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        self.analysis_status_lbl = QLabel()
        self.analysis_status_lbl.setObjectName("SectionTitle")
        self.analysis_status_lbl.setWordWrap(True)
        self.confidence_badge = Badge("unknown", variant="neutral")
        self.cancel_scan_btn = QPushButton()
        self.cancel_scan_btn.setObjectName("Ghost")
        self.cancel_scan_btn.clicked.connect(self.cancel_analysis)
        self.cancel_scan_btn.hide()
        status_row.addWidget(self.analysis_status_lbl, 1)
        status_row.addWidget(self.confidence_badge)
        status_row.addWidget(self.cancel_scan_btn)
        lay.addLayout(status_row)

        self.candidates_lbl = QLabel()
        self.candidates_lbl.setObjectName("FieldLabel")
        lay.addWidget(self.candidates_lbl)

        self.candidates_list = QListWidget()
        self.candidates_list.setMaximumHeight(130)
        self.candidates_list.itemActivated.connect(self._analyze_selected_candidate)
        lay.addWidget(self.candidates_list)

        cand_btns = FlowLayout(spacing=6)
        self.analyze_candidate_btn = QPushButton()
        self.analyze_candidate_btn.clicked.connect(self._analyze_selected_candidate)
        self.use_root_btn = QPushButton()
        self.use_root_btn.setObjectName("Ghost")
        self.use_root_btn.clicked.connect(self._use_parent_as_root)
        cand_btns.addWidget(self.analyze_candidate_btn)
        cand_btns.addWidget(self.use_root_btn)
        lay.addLayout(cand_btns)

        self.analysis_summary = QPlainTextEdit()
        self.analysis_summary.setObjectName("ConsoleLog")
        self.analysis_summary.setReadOnly(True)
        lay.addWidget(self.analysis_summary, 1)
        return w

    def _build_step_proposals(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 4, 6)
        lay.setSpacing(8)

        form = QFormLayout()
        form.setSpacing(6)
        self.id_edit = QLineEdit()
        self.id_edit.setObjectName("UiInput")
        self.name_edit = QLineEdit()
        self.name_edit.setObjectName("UiInput")
        self.lang_edit = QLineEdit()
        self.lang_edit.setObjectName("UiInput")
        self.git_root_edit = QLineEdit()
        self.git_root_edit.setObjectName("UiInput")
        self.venv_edit = QLineEdit()
        self.venv_edit.setObjectName("UiInput")
        self.node_edit = QLineEdit()
        self.node_edit.setObjectName("UiInput")
        self.excludes_edit = QLineEdit()
        self.excludes_edit.setObjectName("UiInput")
        for edit in (
            self.id_edit,
            self.name_edit,
            self.lang_edit,
            self.git_root_edit,
            self.venv_edit,
            self.node_edit,
            self.excludes_edit,
        ):
            edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)

        self._prop_labels: dict[str, QLabel] = {}
        for key, widget in (
            ("workspaces.dlg.id", self.id_edit),
            ("workspaces.dlg.name", self.name_edit),
            ("workspaces.dlg.lang", self.lang_edit),
            ("workspaces.dlg.git_root", self.git_root_edit),
            ("workspaces.dlg.venv", self.venv_edit),
            ("workspaces.dlg.node", self.node_edit),
            ("workspaces.dlg.excludes", self.excludes_edit),
        ):
            lbl = QLabel()
            self._prop_labels[key] = lbl
            form.addRow(lbl, widget)
        lay.addLayout(form)

        lay.addWidget(Divider())
        self.cmds_title_lbl = QLabel()
        self.cmds_title_lbl.setObjectName("FieldLabel")
        self.cmds_title_lbl.setWordWrap(True)
        lay.addWidget(self.cmds_title_lbl)

        self.cmds_host = QWidget()
        self.cmds_layout = QVBoxLayout(self.cmds_host)
        self.cmds_layout.setContentsMargins(0, 0, 0, 0)
        self.cmds_layout.setSpacing(4)
        lay.addWidget(self.cmds_host)

        add_cmd_row = QHBoxLayout()
        add_cmd_row.setSpacing(6)
        self.new_cmd_name_edit = QLineEdit()
        self.new_cmd_name_edit.setObjectName("UiInput")
        self.new_cmd_val_edit = QLineEdit()
        self.new_cmd_val_edit.setObjectName("UiInput")
        self.add_cmd_btn = QPushButton()
        self.add_cmd_btn.clicked.connect(self._on_add_manual_command)
        add_cmd_row.addWidget(self.new_cmd_name_edit, 1)
        add_cmd_row.addWidget(self.new_cmd_val_edit, 2)
        add_cmd_row.addWidget(self.add_cmd_btn)
        lay.addLayout(add_cmd_row)

        lay.addWidget(Divider())
        self.servers_title_lbl = QLabel()
        self.servers_title_lbl.setObjectName("FieldLabel")
        self.servers_title_lbl.setWordWrap(True)
        lay.addWidget(self.servers_title_lbl)

        self.servers_host = QWidget()
        self.servers_layout = QVBoxLayout(self.servers_host)
        self.servers_layout.setContentsMargins(0, 0, 0, 0)
        self.servers_layout.setSpacing(4)
        lay.addWidget(self.servers_host)

        self.existing_servers_lbl = QLabel()
        self.existing_servers_lbl.setObjectName("FieldLabel")
        self.existing_servers_lbl.setWordWrap(True)
        lay.addWidget(self.existing_servers_lbl)

        self.existing_servers_host = QWidget()
        self.existing_servers_layout = QVBoxLayout(self.existing_servers_host)
        self.existing_servers_layout.setContentsMargins(0, 0, 0, 0)
        self.existing_servers_layout.setSpacing(3)
        lay.addWidget(self.existing_servers_host)
        lay.addStretch(1)
        return w

    def _build_step_access(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 4, 6)
        lay.setSpacing(8)

        perm_row = FlowLayout(spacing=8)
        self.perm_read = QCheckBox()
        self.perm_read.setChecked(True)
        self.perm_write = QCheckBox()
        self.perm_delete = QCheckBox()
        self.perm_execute = QCheckBox()
        self.perm_git = QCheckBox()
        for cb in (self.perm_read, self.perm_write, self.perm_delete, self.perm_execute, self.perm_git):
            cb.toggled.connect(self._refresh_preview)
            perm_row.addWidget(cb)
        lay.addLayout(perm_row)

        self.trust_hooks_check = QCheckBox()
        self.trust_hooks_check.toggled.connect(self._refresh_preview)
        lay.addWidget(self.trust_hooks_check)

        lay.addWidget(Divider())
        self.allow_oauth_check = QCheckBox()
        self.allow_oauth_check.setChecked(False)
        self.allow_oauth_check.toggled.connect(self._on_oauth_toggle_changed)
        lay.addWidget(self.allow_oauth_check)

        oauth_form = QFormLayout()
        oauth_form.setSpacing(6)
        self.oauth_mode_combo = SafeComboBox()
        self.oauth_mode_combo.addItem("", "specific")
        self.oauth_mode_combo.addItem("", "all_approved")
        self.oauth_mode_combo.currentIndexChanged.connect(self._on_oauth_toggle_changed)
        self._oauth_mode_lbl = QLabel()
        oauth_form.addRow(self._oauth_mode_lbl, self.oauth_mode_combo)

        self.allowed_clients_edit = QLineEdit()
        self.allowed_clients_edit.setObjectName("UiInput")
        self.allowed_clients_edit.textChanged.connect(self._refresh_preview)
        self._allowed_clients_lbl = QLabel()
        oauth_form.addRow(self._allowed_clients_lbl, self.allowed_clients_edit)

        self.min_profile_combo = SafeComboBox()
        for mp in WORKSPACE_MIN_PROFILES:
            self.min_profile_combo.addItem(mp, mp)
        self.min_profile_combo.currentIndexChanged.connect(self._refresh_preview)
        self._min_profile_lbl = QLabel()
        oauth_form.addRow(self._min_profile_lbl, self.min_profile_combo)
        lay.addLayout(oauth_form)

        self.ack_nested_check = QCheckBox()
        self.ack_nested_check.hide()
        self.ack_nested_check.toggled.connect(self._refresh_preview)
        lay.addWidget(self.ack_nested_check)

        self.preview_title_lbl = QLabel()
        self.preview_title_lbl.setObjectName("FieldLabel")
        self.preview_title_lbl.setWordWrap(True)
        lay.addWidget(self.preview_title_lbl)

        self.preview_view = QPlainTextEdit()
        self.preview_view.setObjectName("ConsoleLog")
        self.preview_view.setReadOnly(True)
        self.preview_view.setMinimumHeight(140)
        lay.addWidget(self.preview_view, 1)

        self._on_oauth_toggle_changed()
        return w

    def _set_mode(self, mode: str) -> None:
        self._mode = "scan" if mode == "scan" else "single"
        self.mode_single_btn.setChecked(self._mode == "single")
        self.mode_scan_btn.setChecked(self._mode == "scan")
        self._update_mode_controls()

    def _update_mode_controls(self) -> None:
        is_scan = self._mode == "scan"
        self.scan_depth_combo.setEnabled(is_scan)

    def _browse_dir(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, tr("workspaces.wizard.path_label"))
        if chosen:
            self.path_edit.setText(chosen)

    def _invalidate_discovery(self) -> None:
        self._generation += 1
        self._analyzing = False
        if self._cancel_event is not None:
            self._cancel_event.set()
        self._discovery = None
        self._last_preview = None

    def is_analyzing(self) -> bool:
        return self._analyzing or (self._worker is not None and self._worker.isRunning())

    def cancel_analysis(self) -> None:
        self._generation += 1
        self._analyzing = False
        if self._cancel_event is not None:
            self._cancel_event.set()
        self.cancel_scan_btn.hide()
        self.analysis_status_lbl.setText(tr("common.cancel"))

    def start_analysis(self, *, override_path: str = "", force_mode: str = "") -> None:
        target = (override_path or self.path_edit.text()).strip()
        if not target:
            SilentMessageBox.warning(self, tr("workspaces.wizard.title"), tr("workspaces.wizard.need_path"))
            return
        mode = force_mode or self._mode
        self._generation += 1
        gen = self._generation
        self._analyzing = True
        if self._cancel_event is not None:
            self._cancel_event.set()
        if self._worker is not None and self._worker.isRunning():
            self._retired_workers.append(self._worker)
        cancel_ev = threading.Event()
        self._cancel_event = cancel_ev

        self._set_step(1)
        self.analysis_status_lbl.setText(tr("workspaces.wizard.analyzing"))
        self.confidence_badge.setText("…")
        self.confidence_badge.set_variant("neutral")
        self.cancel_scan_btn.show()
        self.next_btn.setEnabled(False)
        self.candidates_list.clear()
        self.analysis_summary.clear()

        depth = int(self.scan_depth_combo.currentData() or 2)
        worker = _DiscoveryWorker(
            generation=gen,
            mode=mode,
            target_path=target,
            scan_depth=depth,
            cancel_event=cancel_ev,
            parent=self,
        )
        worker.finished_discovery.connect(self._on_discovery_finished)
        worker.finished.connect(lambda w=worker: self._retired_workers.remove(w) if w in self._retired_workers else None)
        self._worker = worker
        worker.start()

    def _apply_scan_payload(self, payload: object) -> None:
        if isinstance(payload, tuple) and len(payload) == 2 and isinstance(payload[0], list):
            scan_items, scan_diags = payload[0], list(payload[1] or ())
        elif isinstance(payload, list):
            scan_items, scan_diags = list(payload), []
        else:
            return
        self._scan_candidates = list(scan_items)
        self._populate_candidates_list(self._scan_candidates)
        self.analysis_status_lbl.setText(f"{len(self._scan_candidates)} candidate(s) found")
        self.confidence_badge.setText(str(len(self._scan_candidates)))
        self.confidence_badge.set_variant("accent" if (self._scan_candidates and not scan_diags) else "warn")
        summary_lines = [f"- {c.relative_path} [{c.language}] ({c.source})" for c in self._scan_candidates]
        summary_lines.extend(f"[{diag.level.upper()}:{diag.code}] {diag.message}" for diag in scan_diags)
        self.analysis_summary.setPlainText("\n".join(summary_lines) or tr("workspaces.wizard.unknown_hint"))
        self.next_btn.setEnabled(True)

    def _on_discovery_finished(self, generation: int, kind: str, payload: object, error: str) -> None:
        if generation != self._generation:
            return
        self._analyzing = False
        self.cancel_scan_btn.hide()
        if error:
            self.analysis_status_lbl.setText(error)
            self.confidence_badge.setText("error")
            self.confidence_badge.set_variant("err")
            self.analysis_summary.setPlainText(error)
            self.next_btn.setEnabled(False)
            return
        if kind == "scan":
            self._apply_scan_payload(payload)
            return
        if isinstance(payload, WorkspaceDiscoveryResult):
            self._apply_discovery_result(payload)
            self.next_btn.setEnabled(True)

    def _populate_candidates_list(self, candidates: list[SubprojectCandidate]) -> None:
        self.candidates_list.clear()
        for cand in candidates:
            item = QListWidgetItem(f"{cand.relative_path}  [{cand.language} / {cand.confidence}] — {cand.source}")
            item.setData(Qt.ItemDataRole.UserRole, cand.root_path)
            self.candidates_list.addItem(item)
        has_cands = bool(candidates)
        self.candidates_lbl.setVisible(has_cands)
        self.candidates_list.setVisible(has_cands)
        self.analyze_candidate_btn.setVisible(has_cands)
        self.use_root_btn.setVisible(self._mode == "scan")
        if has_cands:
            self.candidates_list.setCurrentRow(0)

    def _analyze_selected_candidate(self) -> None:
        item = self.candidates_list.currentItem()
        if item is None:
            return
        chosen = str(item.data(Qt.ItemDataRole.UserRole) or "").strip()
        if chosen:
            self.path_edit.setText(chosen)
            self._set_mode("single")
            self.start_analysis(override_path=chosen, force_mode="single")

    def _use_parent_as_root(self) -> None:
        parent_dir = self.path_edit.text().strip()
        if parent_dir:
            self._set_mode("single")
            self.start_analysis(override_path=parent_dir, force_mode="single")

    def _apply_discovery_result(self, res: WorkspaceDiscoveryResult) -> None:
        self._discovery = res
        existing_ids = set(self._ws_store.load_workspaces()) if self._ws_store else set()
        unique_id = suggest_unique_workspace_id(res.suggested_id, existing_ids)

        variant = "ok" if res.confidence == "high" else ("warn" if res.confidence in ("medium", "low") else "neutral")
        self.confidence_badge.setText(res.confidence)
        self.confidence_badge.set_variant(variant)
        self.analysis_status_lbl.setText(f"{res.name} — {', '.join(res.stacks) or res.language}")

        if res.subprojects:
            self._populate_candidates_list(list(res.subprojects))
        else:
            self._populate_candidates_list([])

        lines = [
            f"Root: {res.root_path}",
            f"Language / Stacks: {res.language} ({', '.join(res.stacks) or 'generic'})",
            f"{tr('workspaces.wizard.confidence')}: {res.confidence}",
            f"{tr('workspaces.wizard.sources')}: {', '.join(res.sources) or '—'}",
            f"Git: {res.git_root or ('unverified' if res.diagnostics else '—')}",
            f"Python venv: {res.python_venv or '—'}",
            f"Node.js: {res.node_path or '—'}",
        ]
        if res.confidence == "unknown":
            lines.append(tr("workspaces.wizard.unknown_hint"))
        for diag in res.diagnostics:
            lines.append(f"[{diag.level.upper()}:{diag.code}] {diag.message}")
        self.analysis_summary.setPlainText("\n".join(lines))

        self.id_edit.setText(unique_id)
        self.name_edit.setText(res.name)
        self.lang_edit.setText(res.language)
        self.git_root_edit.setText(res.git_root)
        self.venv_edit.setText(res.python_venv)
        self.node_edit.setText(res.node_path)
        self.excludes_edit.setText(", ".join(res.exclude_patterns))

        self._rebuild_command_rows(res.commands)
        self._rebuild_server_rows(res.server_proposals)
        self._rebuild_existing_server_links()

    def _clear_layout(self, lay: QVBoxLayout) -> None:
        while lay.count():
            item = lay.takeAt(0)
            if item is None:
                continue
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def _rebuild_command_rows(self, proposals: tuple[CommandProposal, ...]) -> None:
        self._cmd_rows.clear()
        self._clear_layout(self.cmds_layout)
        for prop in proposals:
            self._append_command_row(prop)

    def _append_command_row(self, prop: CommandProposal) -> None:
        row_w = QWidget()
        row = QHBoxLayout(row_w)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        cb = QCheckBox()
        cb.setChecked(prop.selected)
        name_e = QLineEdit(prop.name)
        name_e.setObjectName("UiInput")
        name_e.setMaximumWidth(130)
        cmd_e = QLineEdit(prop.command)
        cmd_e.setObjectName("UiInput")
        cmd_e.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        src_text = f"[{prop.source}]" + (" ⚠ hooks" if prop.has_lifecycle_hooks else "")
        src_lbl = QLabel(src_text)
        src_lbl.setObjectName("Caption")
        row.addWidget(cb)
        row.addWidget(name_e, 1)
        row.addWidget(cmd_e, 3)
        row.addWidget(src_lbl)
        self.cmds_layout.addWidget(row_w)
        self._cmd_rows.append(_CommandRowWidgets(row_w, cb, name_e, cmd_e, src_lbl))

    def add_manual_command(self, name: str, command: str) -> None:
        clean_name = name.strip()
        clean_cmd = command.strip()
        if not clean_name or not clean_cmd:
            return
        self._append_command_row(
            CommandProposal(name=clean_name, command=clean_cmd, source="manual", selected=True)
        )

    def _on_add_manual_command(self) -> None:
        self.add_manual_command(self.new_cmd_name_edit.text(), self.new_cmd_val_edit.text())
        self.new_cmd_name_edit.clear()
        self.new_cmd_val_edit.clear()

    def _rebuild_server_rows(self, proposals: tuple[ServerProposal, ...]) -> None:
        self._srv_rows.clear()
        self._clear_layout(self.servers_layout)
        if not proposals:
            lbl = QLabel("—")
            lbl.setObjectName("Hint")
            self.servers_layout.addWidget(lbl)
            return
        for prop in proposals:
            row_w = QWidget()
            row = QHBoxLayout(row_w)
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(6)
            cb = QCheckBox()
            cb.setChecked(False)
            name_e = QLineEdit(prop.name)
            name_e.setObjectName("UiInput")
            name_e.setMaximumWidth(170)
            port_txt = f":{prop.port} (unverified)" if prop.port else "no port"
            info = QLabel(f"{prop.template} | {prop.entrypoint} | {port_txt} [{prop.source}]")
            info.setObjectName("Hint")
            info.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            row.addWidget(cb)
            row.addWidget(name_e)
            row.addWidget(info, 1)
            self.servers_layout.addWidget(row_w)
            self._srv_rows.append(_ServerRowWidgets(cb, name_e, prop))

    def _rebuild_existing_server_links(self) -> None:
        self._link_checks.clear()
        self._clear_layout(self.existing_servers_layout)
        try:
            profiles = self._srv_store.load_profiles(strict=False)
        except Exception:  # noqa: BLE001
            profiles = {}
        if not profiles:
            lbl = QLabel("—")
            lbl.setObjectName("Hint")
            self.existing_servers_layout.addWidget(lbl)
            return
        for sname in sorted(profiles):
            prof = profiles[sname]
            cb = QCheckBox(f"{prof.name} ({prof.template}, {prof.cwd})")
            cb.setChecked(False)
            self.existing_servers_layout.addWidget(cb)
            self._link_checks[sname] = cb

    def _on_oauth_toggle_changed(self) -> None:
        allow = self.allow_oauth_check.isChecked()
        self.oauth_mode_combo.setEnabled(allow)
        is_specific = self.oauth_mode_combo.currentData() == "specific"
        self.allowed_clients_edit.setEnabled(allow and is_specific)
        self.min_profile_combo.setEnabled(allow)
        self._refresh_preview()

    def _collect_commands_and_oauth(self) -> tuple[dict[str, str], bool, tuple[str, ...]]:
        commands: dict[str, str] = {}
        for row in self._cmd_rows:
            if not row.enable_cb.isChecked():
                continue
            cname = row.name_edit.text().strip()
            cmd_val = row.cmd_edit.text().strip()
            if cname and cmd_val:
                commands[cname] = cmd_val
        allow_oauth = self.allow_oauth_check.isChecked()
        oauth_mode = str(self.oauth_mode_combo.currentData() or "specific")
        specific_mode = allow_oauth and oauth_mode == "specific"
        allowed_clients = _split_csv(self.allowed_clients_edit.text()) if specific_mode else ()
        if specific_mode and not allowed_clients:
            raise ValueError(tr("workspaces.wizard.need_client_ids"))
        return commands, allow_oauth, allowed_clients

    def _build_selected_servers(self) -> list[ServerProfile]:
        new_servers: list[ServerProfile] = []
        for srow in self._srv_rows:
            if not srow.enable_cb.isChecked():
                continue
            prop = srow.proposal
            sname = srow.name_edit.text().strip() or prop.name
            srv = build_profile_from_template(
                name=sname,
                template=prop.template,
                cwd=prop.cwd,
                host=prop.host,
                port=prop.port,
                executable=prop.executable,
                entrypoint=prop.entrypoint,
                extra_args=prop.extra_args,
                readiness_kind=prop.readiness_kind,
                health_path=prop.health_path,
                autostart=False,
                min_profile="full",
                display_name=prop.display_name,
            )
            new_servers.append(
                ServerProfile(
                    **{
                        **srv.__dict__,
                        "workspace_scoped": True,
                        "autostart": False,
                        "template_params": {
                            **srv.template_params,
                            "wizard_managed_workspace_id": self.id_edit.text().strip(),
                            "manifest_guarded": True,
                            "manifest_digests": dict(prop.manifest_digests),
                        },
                    }
                )
            )
        return new_servers

    def _collect_profile_and_servers(
        self,
    ) -> tuple[WorkspaceProfile, list[ServerProfile], list[str]]:
        if self._discovery is None:
            raise ValueError("Run project analysis first")
        wid = self.id_edit.text().strip()
        commands, allow_oauth, allowed_clients = self._collect_commands_and_oauth()
        selected_servers = self._build_selected_servers()
        profile = WorkspaceProfile(
            workspace_id=wid,
            name=self.name_edit.text().strip() or wid,
            root_path=self._discovery.root_path,
            language=self.lang_edit.text().strip(),
            git_root=self.git_root_edit.text().strip(),
            python_venv=self.venv_edit.text().strip(),
            node_path=self.node_edit.text().strip(),
            commands=commands,
            exclude_patterns=_split_csv(self.excludes_edit.text()),
            permissions=WorkspacePermissions(
                read=self.perm_read.isChecked(),
                write=self.perm_write.isChecked(),
                delete=self.perm_delete.isChecked(),
                execute=self.perm_execute.isChecked(),
                git=self.perm_git.isChecked(),
            ),
            allowed_clients=allowed_clients,
            min_profile=str(self.min_profile_combo.currentData() or "allowlist"),
            allow_oauth_clients=allow_oauth,
            manifest_digests=dict(self._discovery.manifest_digests),
            manifest_guarded=True,
            wizard_servers=tuple(s.name for s in selected_servers),
            trust_git_hooks=self.trust_hooks_check.isChecked(),
            enabled=True,
        )
        linked_existing = [sname for sname, cb in self._link_checks.items() if cb.isChecked()]
        return profile, selected_servers, linked_existing

    def _refresh_preview(self) -> None:
        if self.stack.currentIndex() != 3 or self._discovery is None:
            return
        try:
            profile, new_servers, linked_existing = self._collect_profile_and_servers()
            preview = self._coordinator.prepare_addition_preview(
                profile,
                new_servers=new_servers,
                link_existing_servers=linked_existing,
                expected_manifest_digests=self._discovery.manifest_digests,
                expected_root_identity=self._discovery.root_identity,
            )
            self._last_preview = preview
            if preview.nested_workspaces:
                self.ack_nested_check.setText(
                    f"{tr('workspaces.wizard.ack_nested')}: {', '.join(preview.nested_workspaces)}"
                )
                self.ack_nested_check.show()
            else:
                self.ack_nested_check.setChecked(False)
                self.ack_nested_check.hide()

            body = {
                "workspace": {
                    "workspace_id": preview.profile.workspace_id,
                    "name": preview.profile.name,
                    "root_path": preview.profile.root_path,
                    "language": preview.profile.language,
                    "commands": preview.profile.commands,
                    "linked_servers": list(preview.profile.linked_servers),
                },
                "new_servers": [
                    {
                        "name": s.name,
                        "template": s.template,
                        "argv": shlex.join(s.argv),
                        "autostart": s.autostart,
                        "workspace_scoped": s.workspace_scoped,
                    }
                    for s in preview.new_servers
                ],
                "link_existing_servers": list(preview.link_existing_servers),
                "effective_permissions": preview.effective_permissions,
                "conflicts": list(preview.conflicts),
                "warnings": list(preview.warnings),
            }
            self.preview_view.setPlainText(
                redact_discovery_text(json.dumps(body, indent=2, ensure_ascii=False))
            )
        except Exception as exc:  # noqa: BLE001
            self._last_preview = None
            self.preview_view.setPlainText(redact_discovery_text(str(exc)))

    def _set_step(self, idx: int) -> None:
        self.stack.setCurrentIndex(idx)
        for i, pill in enumerate(self._step_pills):
            pill.set_variant("accent" if i == idx else ("ok" if i < idx else "neutral"))
        self.back_btn.setEnabled(idx > 0)
        if idx == 0:
            self.next_btn.setText(tr("workspaces.wizard.btn.analyze"))
            self.next_btn.setEnabled(True)
        elif idx == 3:
            self.next_btn.setText(tr("workspaces.wizard.btn.commit"))
            self.next_btn.setEnabled(True)
            self._refresh_preview()
        else:
            self.next_btn.setText(tr("workspaces.wizard.btn.next"))
            self.next_btn.setEnabled(self._discovery is not None or (idx == 1 and self._mode == "scan"))

    def go_back(self) -> None:
        cur = self.stack.currentIndex()
        if cur > 0:
            self._set_step(cur - 1)

    def go_next(self) -> None:
        cur = self.stack.currentIndex()
        if cur == 0:
            self.start_analysis()
            return
        if cur == 1:
            if self._discovery is None:
                if self._scan_candidates:
                    self._analyze_selected_candidate()
                else:
                    self._use_parent_as_root()
                return
            self._set_step(2)
            return
        if cur == 2:
            self._set_step(3)
            return
        if cur == 3:
            self.commit()

    def _on_primary_clicked(self) -> None:
        self.go_next()

    def commit(self) -> None:
        if self._committing:
            return
        self._committing = True
        self.next_btn.setEnabled(False)
        try:
            self._refresh_preview()
            if self._last_preview is None or self._discovery is None:
                raise ValueError(self.preview_view.toPlainText() or "Invalid workspace configuration")
            if self._last_preview.conflicts:
                raise ValueError("; ".join(self._last_preview.conflicts))
            profile, new_servers, linked_existing = self._collect_profile_and_servers()
            res = self._coordinator.commit_workspace_addition(
                profile,
                new_servers=new_servers,
                link_existing_servers=linked_existing,
                expected_state_fingerprint=self._last_preview.snapshot.state_fingerprint,
                expected_root_identity=self._last_preview.snapshot.root_identity,
                expected_manifest_digests=self._last_preview.snapshot.manifest_digests,
                acknowledge_nested=self.ack_nested_check.isChecked(),
                expected_nested_ids=self._last_preview.nested_workspaces,
            )
            self.committed_workspace_id = res["workspace"].workspace_id
            self.committed_server_names = tuple(res.get("created_servers", ()))
            self.accept()
        except Exception as exc:  # noqa: BLE001
            self._refresh_preview()
            SilentMessageBox.warning(self, tr("workspaces.wizard.title"), redact_discovery_text(str(exc)))
        finally:
            self._committing = False
            self.next_btn.setEnabled(True)

    def _request_manual_form(self) -> None:
        self.manual_requested = True
        self.reject()

    def _stop_worker_on_exit(self) -> None:
        self._generation += 1
        self._analyzing = False
        if self._cancel_event is not None:
            self._cancel_event.set()
        for w in [*self._retired_workers, self._worker]:
            if w is not None and w.isRunning():
                w.wait(1500)
        self._retired_workers.clear()

    def reject(self) -> None:
        self._stop_worker_on_exit()
        super().reject()

    def closeEvent(self, event) -> None:  # noqa: ANN001
        self._stop_worker_on_exit()
        super().closeEvent(event)

    def retranslate(self) -> None:
        self.setWindowTitle(tr("workspaces.wizard.title"))
        self._lead_lbl.setText(tr("workspaces.wizard.lead"))
        step_keys = (
            "workspaces.wizard.step.source",
            "workspaces.wizard.step.analysis",
            "workspaces.wizard.step.proposals",
            "workspaces.wizard.step.access",
        )
        for pill, key in zip(self._step_pills, step_keys, strict=True):
            pill.setText(tr(key))
        self.mode_single_btn.setText(tr("workspaces.wizard.mode.single"))
        self.mode_scan_btn.setText(tr("workspaces.wizard.mode.scan"))
        self._path_form_lbl.setText(tr("workspaces.wizard.path_label"))
        self.path_edit.setPlaceholderText(tr("workspaces.wizard.path_ph"))
        self.browse_btn.setText(tr("workspaces.dlg.browse"))
        self._depth_form_lbl.setText(tr("workspaces.wizard.scan_depth"))
        self._readonly_note_lbl.setText(tr("workspaces.wizard.readonly_note"))
        self.manual_btn.setText(tr("workspaces.wizard.manual_btn"))
        self.cancel_scan_btn.setText(tr("workspaces.wizard.cancel_scan"))
        self.candidates_lbl.setText(tr("workspaces.wizard.candidates"))
        self.analyze_candidate_btn.setText(tr("workspaces.wizard.btn.analyze"))
        self.use_root_btn.setText(tr("workspaces.wizard.use_root"))
        for key, lbl in self._prop_labels.items():
            lbl.setText(tr(key))
        self.cmds_title_lbl.setText(tr("workspaces.wizard.cmds_title"))
        self.new_cmd_name_edit.setPlaceholderText(tr("workspaces.wizard.cmd_name_ph"))
        self.new_cmd_val_edit.setPlaceholderText(tr("workspaces.wizard.cmd_val_ph"))
        self.add_cmd_btn.setText(tr("workspaces.wizard.add_cmd"))
        self.servers_title_lbl.setText(tr("workspaces.wizard.servers_title"))
        self.existing_servers_lbl.setText(tr("workspaces.wizard.existing_servers"))
        self.perm_read.setText(tr("workspaces.dlg.perm_read"))
        self.perm_write.setText(tr("workspaces.dlg.perm_write"))
        self.perm_delete.setText(tr("workspaces.dlg.perm_delete"))
        self.perm_execute.setText(tr("workspaces.dlg.perm_execute"))
        self.perm_git.setText(tr("workspaces.dlg.perm_git"))
        self.trust_hooks_check.setText(tr("workspaces.dlg.trust_hooks"))
        self.allow_oauth_check.setText(tr("workspaces.dlg.allow_oauth_clients"))
        self._oauth_mode_lbl.setText(tr("workspaces.wizard.oauth_mode"))
        self.oauth_mode_combo.setItemText(0, tr("workspaces.wizard.oauth_specific"))
        self.oauth_mode_combo.setItemText(1, tr("workspaces.wizard.oauth_all"))
        self._allowed_clients_lbl.setText(tr("workspaces.dlg.allowed_clients"))
        self.allowed_clients_edit.setPlaceholderText(tr("workspaces.dlg.allowed_clients_ph"))
        self._min_profile_lbl.setText(tr("workspaces.dlg.min_profile"))
        self.preview_title_lbl.setText(tr("workspaces.wizard.preview_title"))
        self.back_btn.setText(tr("workspaces.wizard.btn.back"))
        self.cancel_btn.setText(tr("common.cancel"))
        idx = self.stack.currentIndex()
        self.next_btn.setText(
            tr("workspaces.wizard.btn.analyze")
            if idx == 0
            else (tr("workspaces.wizard.btn.commit") if idx == 3 else tr("workspaces.wizard.btn.next"))
        )
