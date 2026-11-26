"""Automation, Monitoring, MCP Playground, Backup/Restore & Staged Updater page (Stage 11)."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app import __version__
from app.core.redaction import SecretRedactor
from app.paths import user_data_dir
from app.ui.components.cards import Divider, EmptyState, FlowLayout, Section
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.silent_dialog import SilentDialog
from app.ui.components.table import DataTable
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from backend.automation.backup_updater import BackupManager, StagedUpdater
from backend.automation.monitoring import (
    MetricsRegistry,
    collect_system_snapshot,
    export_redacted_diagnostics,
    filter_audit_entries,
)
from backend.automation.scheduler import AutomationScheduler, ScheduleSpec
from backend.tool_registry import DEFAULT_REGISTRY

_PROFILE_RANK = {"safe": 0, "allowlist": 1, "full": 2}


def run_local_playground_call(
    tool_name: str,
    arguments: dict[str, Any],
    profile: str,
    *,
    config_root: Path,
    redactor: SecretRedactor,
) -> dict[str, Any]:
    """Safely test-run read-only/local registry tools in Playground with fail-closed profile checks."""
    if profile not in _PROFILE_RANK:
        return {
            "allowed": False,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "error": f"Unknown profile: {profile!r}",
        }
    spec = DEFAULT_REGISTRY._specs.get(tool_name)
    if spec is None:
        return {
            "allowed": False,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "error": f"Unknown MCP tool: {tool_name!r}",
        }
    if _PROFILE_RANK[profile] < _PROFILE_RANK.get(spec.min_profile, 99):
        return {
            "allowed": False,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "is_error": True,
            "error": (
                f"Denied: tool '{tool_name}' requires profile '{spec.min_profile}' "
                f"(selected: '{profile}')"
            ),
        }

    if tool_name == "server_info":
        return {
            "allowed": True,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "is_error": False,
            "content": [{"type": "text", "text": "MCP app ready; transport=streamable-http"}],
            "structured": {"status": "ready", "profile": profile},
        }
    if tool_name == "device_list":
        from backend.remote.manager import RemoteManager
        from backend.remote.store import DeviceStore

        mgr = RemoteManager(DeviceStore(config_root / "remote" / "devices.json"), redactor=redactor)
        data = mgr.list_devices()
        return {
            "allowed": True,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "is_error": False,
            "structured": data,
        }
    if tool_name == "workspace_list":
        from backend.workspaces.store import WorkspaceStore

        st = WorkspaceStore(config_root / "workspaces" / "workspaces.json")
        return {
            "allowed": True,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "is_error": False,
            "structured": {"workspaces": [w.to_dict() for w in st.list_workspaces()]},
        }
    if tool_name == "extension_list":
        from backend.extensions.store import ExtensionStore

        ext_st = ExtensionStore(config_root / "extensions")
        return {
            "allowed": True,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "is_error": False,
            "structured": {"extensions": [e.to_dict() for e in ext_st.list_records()]},
        }
    if tool_name == "server_list":
        from backend.servers.store import ServerConfigStore

        srv_st = ServerConfigStore(config_root / "servers" / "managed_servers.json")
        return {
            "allowed": True,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "is_error": False,
            "structured": {"servers": [s.to_dict() for s in srv_st.list_servers()]},
        }
    return {
        "allowed": True,
        "live_execution": True,
        "profile": profile,
        "tool_name": tool_name,
        "is_error": False,
        "content": [
            {
                "type": "text",
                "text": (
                    f"Authorized under profile '{profile}' (min_profile='{spec.min_profile}'). "
                    f"Run MCP server via Start/headless for full live runtime execution of '{tool_name}'."
                ),
            }
        ],
        "arguments": dict(arguments),
    }


class ScheduleDialog(SilentDialog):
    """Modal editor for creating a ScheduleSpec."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("automation.dlg.title"))
        self.setMinimumWidth(480)
        self.saved_spec: ScheduleSpec | None = None

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(6)

        self.id_edit = QLineEdit()
        self.id_edit.setObjectName("UiInput")
        self.id_edit.setPlaceholderText("daily-health")
        self.name_edit = QLineEdit()
        self.name_edit.setObjectName("UiInput")
        self.trigger_combo = SafeComboBox()
        for kind in ("cron", "interval", "startup", "event"):
            self.trigger_combo.addItem(kind, kind)
        self.cron_edit = QLineEdit("*/5 * * * *")
        self.cron_edit.setObjectName("UiInput")
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(5, 86400)
        self.interval_spin.setValue(300)
        self.event_edit = QLineEdit()
        self.event_edit.setObjectName("UiInput")
        self.event_edit.setPlaceholderText("tunnel.started")
        self.tz_edit = QLineEdit("UTC")
        self.tz_edit.setObjectName("UiInput")
        self.tool_combo = SafeComboBox()
        for tname in sorted(DEFAULT_REGISTRY.registered_names()):
            self.tool_combo.addItem(tname, tname)
        self.args_edit = QLineEdit("{}")
        self.args_edit.setObjectName("UiInput")
        self.misfire_combo = SafeComboBox()
        for pol in ("skip", "coalesce", "run_once"):
            self.misfire_combo.addItem(pol, pol)
        self.conc_combo = SafeComboBox()
        for pol in ("forbid", "allow"):
            self.conc_combo.addItem(pol, pol)
        self.safe_retry_chk = QCheckBox(tr("automation.dlg.safe_retry"))
        self.retries_spin = QSpinBox()
        self.retries_spin.setRange(0, 3)

        form.addRow(tr("automation.dlg.id"), self.id_edit)
        form.addRow(tr("automation.dlg.name"), self.name_edit)
        form.addRow(tr("automation.dlg.trigger"), self.trigger_combo)
        form.addRow(tr("automation.dlg.cron"), self.cron_edit)
        form.addRow(tr("automation.dlg.interval"), self.interval_spin)
        form.addRow(tr("automation.dlg.event"), self.event_edit)
        form.addRow(tr("automation.dlg.tz"), self.tz_edit)
        form.addRow(tr("automation.dlg.tool"), self.tool_combo)
        form.addRow(tr("automation.dlg.args"), self.args_edit)
        form.addRow(tr("automation.dlg.misfire"), self.misfire_combo)
        form.addRow(tr("automation.dlg.concurrency"), self.conc_combo)
        form.addRow("", self.safe_retry_chk)
        form.addRow(tr("automation.dlg.retries"), self.retries_spin)
        layout.addLayout(form)

        self.err_lbl = QLabel()
        self.err_lbl.setObjectName("Error")
        self.err_lbl.setWordWrap(True)
        layout.addWidget(self.err_lbl)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def _accept(self) -> None:
        try:
            args = json.loads(self.args_edit.text().strip() or "{}")
            if not isinstance(args, dict):
                raise ValueError("Arguments JSON must be an object")
            self.saved_spec = ScheduleSpec(
                schedule_id=self.id_edit.text().strip(),
                name=self.name_edit.text().strip() or self.id_edit.text().strip(),
                trigger_type=str(self.trigger_combo.currentData()),
                tool_name=str(self.tool_combo.currentData()),
                arguments=args,
                cron_expr=self.cron_edit.text().strip(),
                interval_seconds=int(self.interval_spin.value()),
                event_name=self.event_edit.text().strip(),
                timezone_name=self.tz_edit.text().strip() or "UTC",
                misfire_policy=str(self.misfire_combo.currentData()),
                concurrency_policy=str(self.conc_combo.currentData()),
                safe_retry=self.safe_retry_chk.isChecked(),
                max_retries=int(self.retries_spin.value()),
            )
            self.accept()
        except Exception as exc:  # noqa: BLE001
            self.err_lbl.setText(str(exc))


class AutomationPage(PageScaffold):
    """Automation Scheduler, Monitoring, MCP Playground, Backup/Restore & Staged Updater."""

    status_message = pyqtSignal(str, str)

    def __init__(
        self,
        *,
        automation_dir: Path | None = None,
        config_root: Path | None = None,
        redactor: SecretRedactor | None = None,
        playground_runner: Callable[[str, dict[str, Any], str], dict[str, Any]] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(scroll=False, parent=parent)
        self._automation_dir = Path(automation_dir) if automation_dir else (user_data_dir() / "automation")
        self._config_root = Path(config_root) if config_root else user_data_dir()
        self._redactor = redactor or SecretRedactor()
        self._playground_runner = playground_runner
        self.scheduler = AutomationScheduler(self._automation_dir, redactor=self._redactor)
        self.metrics = MetricsRegistry()
        self.updater = StagedUpdater(self._automation_dir / "updates")
        self._schedules: list[dict[str, Any]] = []

        self.set_header(tr("automation.title"), tr("automation.lead"))

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_schedules_tab(), tr("automation.tab.schedules"))
        self.tabs.addTab(self._build_monitoring_tab(), tr("automation.tab.monitoring"))
        self.tabs.addTab(self._build_playground_tab(), tr("automation.tab.playground"))
        self.tabs.addTab(self._build_backup_tab(), tr("automation.tab.backup"))
        self.content.addWidget(self.tabs, 1)

        self.reload()

    # ------------------------------------------------------------------ tabs
    def _build_schedules_tab(self) -> QWidget:
        page = QWidget()
        col = QVBoxLayout(page)
        col.setContentsMargins(0, 10, 0, 0)
        col.setSpacing(12)

        toolbar = FlowLayout(spacing=6)
        self.add_sched_btn = QPushButton(tr("automation.sched.add"))
        self.add_sched_btn.setObjectName("Accent")
        self.add_sched_btn.clicked.connect(self.open_add_schedule_dialog)
        self.run_sched_btn = QPushButton(tr("automation.sched.run"))
        self.run_sched_btn.setObjectName("Ghost")
        self.run_sched_btn.clicked.connect(self.run_selected_schedule)
        self.del_sched_btn = QPushButton(tr("automation.sched.delete"))
        self.del_sched_btn.setObjectName("Danger")
        self.del_sched_btn.clicked.connect(self.delete_selected_schedule)
        self.refresh_sched_btn = QPushButton(tr("automation.sched.refresh"))
        self.refresh_sched_btn.setObjectName("Ghost")
        self.refresh_sched_btn.clicked.connect(self.reload)
        for btn in (self.add_sched_btn, self.run_sched_btn, self.del_sched_btn, self.refresh_sched_btn):
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            toolbar.addWidget(btn)
        col.addLayout(toolbar)

        sched_sec = Section(tr("automation.sched.table_title"), spacing=6)
        self._sched_hdr = sched_sec.header
        self.schedules_table = DataTable([
            tr("automation.col.id"),
            tr("automation.col.name"),
            tr("automation.col.trigger"),
            tr("automation.col.tool"),
            tr("automation.col.tz"),
            tr("automation.col.status"),
        ])
        self.schedules_table.setMinimumHeight(130)
        sched_sec.body.addWidget(self.schedules_table, 1)
        self.empty_state = EmptyState(
            "automation", tr("automation.sched.empty_title"), tr("automation.sched.empty_desc")
        )
        sched_sec.body.addWidget(self.empty_state)
        col.addWidget(sched_sec, 1)

        col.addWidget(Divider())

        hist_sec = Section(tr("automation.sched.history_title"), spacing=6)
        self._hist_hdr = hist_sec.header
        self.history_view = QPlainTextEdit()
        self.history_view.setObjectName("ConsoleLog")
        self.history_view.setReadOnly(True)
        self.history_view.setMaximumHeight(110)
        hist_sec.body.addWidget(self.history_view)
        col.addWidget(hist_sec)
        return page

    def _build_monitoring_tab(self) -> QWidget:
        page = QWidget()
        col = QVBoxLayout(page)
        col.setContentsMargins(0, 10, 0, 0)
        col.setSpacing(12)

        self._admin_notice_lbl = QLabel(tr("automation.mon.admin_notice"))
        self._admin_notice_lbl.setWordWrap(True)
        self._admin_notice_lbl.setObjectName("Hint")
        col.addWidget(self._admin_notice_lbl)
        col.addWidget(Divider())

        controls = QHBoxLayout()
        controls.setSpacing(6)
        self.audit_filter_input = QLineEdit()
        self.audit_filter_input.setObjectName("UiInput")
        self.audit_filter_input.setPlaceholderText(tr("automation.mon.audit_filter"))
        self.audit_filter_input.textChanged.connect(self.refresh_monitoring)
        controls.addWidget(self.audit_filter_input, 1)
        self.mon_refresh_btn = QPushButton(tr("automation.mon.refresh"))
        self.mon_refresh_btn.setObjectName("Ghost")
        self.mon_refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.mon_refresh_btn.clicked.connect(self.refresh_monitoring)
        self.mon_export_btn = QPushButton(tr("automation.mon.export"))
        self.mon_export_btn.setObjectName("Accent")
        self.mon_export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.mon_export_btn.clicked.connect(lambda: self.export_diagnostics())
        controls.addWidget(self.mon_refresh_btn)
        controls.addWidget(self.mon_export_btn)
        col.addLayout(controls)

        snap_sec = Section(tr("automation.mon.snapshot_title"), spacing=6)
        self._snap_hdr = snap_sec.header
        self.metrics_view = QPlainTextEdit()
        self.metrics_view.setObjectName("ConsoleLog")
        self.metrics_view.setReadOnly(True)
        snap_sec.body.addWidget(self.metrics_view, 1)
        col.addWidget(snap_sec, 1)

        col.addWidget(Divider())

        audit_sec = Section(tr("automation.mon.audit_title"), spacing=6)
        self._audit_hdr = audit_sec.header
        self.audit_view = QPlainTextEdit()
        self.audit_view.setObjectName("ConsoleLog")
        self.audit_view.setReadOnly(True)
        self.audit_view.setMaximumHeight(140)
        audit_sec.body.addWidget(self.audit_view)
        col.addWidget(audit_sec)
        return page

    def _build_playground_tab(self) -> QWidget:
        page = QWidget()
        col = QVBoxLayout(page)
        col.setContentsMargins(0, 10, 0, 0)
        col.setSpacing(12)

        self._live_warn_lbl = QLabel(tr("automation.playground.live_warning"))
        self._live_warn_lbl.setWordWrap(True)
        self._live_warn_lbl.setObjectName("Error")
        col.addWidget(self._live_warn_lbl)
        col.addWidget(Divider())

        row = QHBoxLayout()
        row.setSpacing(6)
        self.playground_profile = SafeComboBox()
        for prof in ("safe", "allowlist", "full"):
            self.playground_profile.addItem(prof, prof)
        self.playground_tool = SafeComboBox()
        for tname in sorted(DEFAULT_REGISTRY.registered_names()):
            self.playground_tool.addItem(tname, tname)
        self.playground_tool.currentIndexChanged.connect(self._update_playground_hint)
        self.playground_run_btn = QPushButton(tr("automation.playground.run"))
        self.playground_run_btn.setObjectName("Accent")
        self.playground_run_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.playground_run_btn.clicked.connect(lambda: self.run_playground())
        row.addWidget(self.playground_profile)
        row.addWidget(self.playground_tool, 1)
        row.addWidget(self.playground_run_btn)
        col.addLayout(row)

        self.playground_hint = QLabel()
        self.playground_hint.setObjectName("Hint")
        self.playground_hint.setWordWrap(True)
        col.addWidget(self.playground_hint)

        self.playground_args = QPlainTextEdit("{}")
        self.playground_args.setObjectName("ConsoleLog")
        self.playground_args.setMaximumHeight(86)
        col.addWidget(self.playground_args)

        col.addWidget(Divider())

        out_sec = Section(tr("automation.playground.output_title"), spacing=6)
        self._pg_out_hdr = out_sec.header
        self.playground_output = QPlainTextEdit()
        self.playground_output.setObjectName("ConsoleLog")
        self.playground_output.setReadOnly(True)
        out_sec.body.addWidget(self.playground_output, 1)
        col.addWidget(out_sec, 1)
        self._update_playground_hint()
        return page

    def _build_backup_tab(self) -> QWidget:
        page = QWidget()
        col = QVBoxLayout(page)
        col.setContentsMargins(0, 10, 0, 0)
        col.setSpacing(14)

        b_sec = Section(
            tr("automation.backup.title"),
            tr("automation.backup.dpapi_notice"),
            spacing=8,
        )
        self._backup_hdr = b_sec.header
        b_row = FlowLayout(spacing=6)
        self.backup_create_btn = QPushButton(tr("automation.backup.create"))
        self.backup_create_btn.setObjectName("Accent")
        self.backup_create_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.backup_create_btn.clicked.connect(self._on_create_backup_clicked)
        self.backup_restore_btn = QPushButton(tr("automation.backup.restore"))
        self.backup_restore_btn.setObjectName("Ghost")
        self.backup_restore_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.backup_restore_btn.clicked.connect(self._on_restore_backup_clicked)
        b_row.addWidget(self.backup_create_btn)
        b_row.addWidget(self.backup_restore_btn)
        b_sec.body.addLayout(b_row)
        self.backup_status = QLabel("")
        self.backup_status.setObjectName("Hint")
        self.backup_status.setWordWrap(True)
        b_sec.body.addWidget(self.backup_status)
        col.addWidget(b_sec)

        col.addWidget(Divider())

        u_sec = Section(
            tr("automation.updater.title"),
            tr("automation.updater.notice", version=__version__),
            spacing=8,
        )
        self._updater_hdr = u_sec.header
        u_row = QHBoxLayout()
        u_row.setSpacing(8)
        self.updater_check_btn = QPushButton(tr("automation.updater.check"))
        self.updater_check_btn.setObjectName("Ghost")
        self.updater_check_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.updater_check_btn.clicked.connect(self.check_for_updates)
        u_row.addWidget(self.updater_check_btn)
        u_row.addStretch(1)
        u_sec.body.addLayout(u_row)
        self.updater_status = QLabel(
            tr("automation.updater.idle", auto_install="OFF")
        )
        self.updater_status.setObjectName("Hint")
        self.updater_status.setWordWrap(True)
        u_sec.body.addWidget(self.updater_status)
        col.addWidget(u_sec)
        col.addStretch(1)
        return page

    # ------------------------------------------------------------------ actions
    def _reload_schedules_table(self) -> None:
        self._schedules = self.scheduler.list_schedules()
        has = bool(self._schedules)
        self.schedules_table.setVisible(has)
        self.empty_state.setVisible(not has)
        self.schedules_table.setRowCount(len(self._schedules))
        for r, sp in enumerate(self._schedules):
            trig = sp.get("trigger_type", "")
            if trig == "cron":
                trig_desc = f"cron ({sp.get('cron_expr', '')})"
            elif trig == "interval":
                trig_desc = f"every {sp.get('interval_seconds', 0)}s"
            elif trig == "event":
                trig_desc = f"event ({sp.get('event_name', '')})"
            else:
                trig_desc = trig
            status = "active" if sp.get("enabled") else f"paused ({sp.get('paused_reason', '')})"
            vals = [
                str(sp.get("schedule_id", "")),
                str(sp.get("name", "")),
                trig_desc,
                str(sp.get("tool_name", "")),
                str(sp.get("timezone_name", "UTC")),
                status,
            ]
            for c, v in enumerate(vals):
                self.schedules_table.setItem(r, c, QTableWidgetItem(v))
        self.schedules_table.resizeColumnsToContents()
        hist = self.scheduler.list_history(limit=25)
        self.history_view.setPlainText(
            "\n".join(
                f"[{h.get('status')}] {h.get('schedule_id')} ({h.get('trigger')}) "
                f"{h.get('error') or h.get('result_summary') or ''}"
                for h in hist
            )
        )

    def reload(self) -> None:
        self._reload_schedules_table()
        self.refresh_monitoring()

    def create_schedule(self, spec: ScheduleSpec) -> dict[str, Any]:
        saved = self.scheduler.upsert_schedule(spec, actor_id="owner", actor_profile="full")
        self.status_message.emit(tr("automation.toast.saved", name=spec.name), "ok")
        self.reload()
        return saved

    def open_add_schedule_dialog(self) -> None:
        dlg = ScheduleDialog(self)
        if dlg.exec() == SilentDialog.DialogCode.Accepted and dlg.saved_spec is not None:
            self.create_schedule(dlg.saved_spec)

    def _selected_schedule_id(self) -> str | None:
        row = self.schedules_table.currentRow()
        if 0 <= row < len(self._schedules):
            return str(self._schedules[row]["schedule_id"])
        return None

    def run_selected_schedule(self) -> None:
        sid = self._selected_schedule_id()
        if not sid:
            return
        res = self.scheduler.trigger_now(sid, trigger="manual_ui")
        self.status_message.emit(tr("automation.toast.ran", sid=sid, status=res.get("status", "")), "info")
        self.reload()

    def delete_selected_schedule(self) -> None:
        sid = self._selected_schedule_id()
        if not sid:
            return
        self.scheduler.remove_schedule(sid, actor_id="owner", actor_profile="full")
        self.status_message.emit(tr("automation.toast.deleted", sid=sid), "ok")
        self.reload()

    def _read_audit_lines(self) -> list[str]:
        candidates = (
            self._config_root / "server" / "mcp_audit.log",
            self._config_root / "mcp_audit.log",
        )
        for p in candidates:
            if p.is_file():
                try:
                    return p.read_text(encoding="utf-8", errors="replace").splitlines()[-500:]
                except OSError:
                    pass
        return []

    def refresh_monitoring(self) -> None:
        snap = collect_system_snapshot(
            self.metrics,
            scheduler_stats={"schedules": len(self._schedules)},
        )
        self.metrics_view.setPlainText(json.dumps(snap, indent=2, ensure_ascii=False))
        filtered = filter_audit_entries(
            self._read_audit_lines(),
            query=self.audit_filter_input.text().strip(),
            limit=100,
        )
        self.audit_view.setPlainText("\n".join(filtered) if filtered else tr("automation.mon.no_audit"))

    def export_diagnostics(self, dest_path: Path | None = None) -> str:
        snap = collect_system_snapshot(
            self.metrics,
            scheduler_stats={"schedules": len(self._schedules)},
        )
        bundle = export_redacted_diagnostics(
            snap,
            audit_lines=self._read_audit_lines(),
            redactor=self._redactor,
        )
        if dest_path is not None:
            out = Path(dest_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(bundle, encoding="utf-8")
            self.status_message.emit(tr("automation.toast.diag_exported", path=str(out)), "ok")
        else:
            out = self._automation_dir / f"diagnostics-{int(time.time())}.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(bundle, encoding="utf-8")
            self.metrics_view.setPlainText(bundle)
            self.status_message.emit(tr("automation.toast.diag_exported", path=str(out)), "ok")
        return bundle

    def _update_playground_hint(self) -> None:
        tname = str(self.playground_tool.currentData() or "server_info")
        spec = DEFAULT_REGISTRY._specs.get(tname)
        if spec is None:
            self.playground_hint.setText("")
            return
        self.playground_hint.setText(
            f"category={spec.category} | min_profile={spec.min_profile} | requires_execution={spec.requires_execution}"
        )

    def run_playground(
        self,
        *,
        tool_name: str | None = None,
        arguments: dict[str, Any] | None = None,
        profile: str | None = None,
    ) -> dict[str, Any]:
        tname = tool_name or str(self.playground_tool.currentData() or "server_info")
        prof = profile or str(self.playground_profile.currentData() or "safe")
        t0 = time.monotonic()
        if arguments is None:
            try:
                parsed = json.loads(self.playground_args.toPlainText().strip() or "{}")
                if not isinstance(parsed, dict):
                    raise ValueError("Playground arguments JSON must be an object")
                args_dict = parsed
            except Exception as exc:  # noqa: BLE001
                self.metrics.record_call(tname, (time.monotonic() - t0) * 1000.0, error=True)
                err_res = {"allowed": False, "live_execution": True, "error": str(exc)}
                self.playground_output.setPlainText(json.dumps(err_res, indent=2, ensure_ascii=False))
                return err_res
        else:
            args_dict = dict(arguments)

        runner = self._playground_runner or (
            lambda tn, ag, pr: run_local_playground_call(
                tn, ag, pr, config_root=self._config_root, redactor=self._redactor
            )
        )
        res = runner(tname, args_dict, prof)
        is_err = (not bool(res.get("allowed", False))) or bool(res.get("is_error", False))
        self.metrics.record_call(tname, (time.monotonic() - t0) * 1000.0, error=is_err)
        self.playground_output.setPlainText(json.dumps(res, indent=2, ensure_ascii=False, default=str))
        self.refresh_monitoring()
        return res

    def create_backup_to(self, dest_zip: Path) -> dict[str, Any]:
        res = BackupManager.create_backup(self._config_root, dest_zip)
        self.backup_status.setText(
            tr("automation.backup.created_msg", count=res["file_count"], path=res["path"])
        )
        self.status_message.emit(
            tr("automation.backup.created_msg", count=res["file_count"], path=res["path"]), "ok"
        )
        return res

    def restore_backup_from(self, src_zip: Path) -> dict[str, Any]:
        res = BackupManager.restore_backup(src_zip, self._config_root)
        self.backup_status.setText(
            tr("automation.backup.restored_msg", count=len(res["restored_files"]))
        )
        self.status_message.emit(
            tr("automation.backup.restored_msg", count=len(res["restored_files"])), "ok"
        )
        self.reload()
        return res

    def _on_create_backup_clicked(self) -> None:
        dest, _ = QFileDialog.getSaveFileName(
            self,
            tr("automation.backup.create"),
            str(self._automation_dir / "mcpapp-backup.zip"),
            "ZIP (*.zip)",
        )
        if dest:
            try:
                self.create_backup_to(Path(dest))
            except Exception as exc:  # noqa: BLE001
                self.backup_status.setText(str(exc))

    def _on_restore_backup_clicked(self) -> None:
        src, _ = QFileDialog.getOpenFileName(
            self,
            tr("automation.backup.restore"),
            str(self._automation_dir),
            "ZIP (*.zip)",
        )
        if src:
            try:
                self.restore_backup_from(Path(src))
            except Exception as exc:  # noqa: BLE001
                self.backup_status.setText(str(exc))

    def check_for_updates(self) -> None:
        try:
            cand = self.updater.fetch_latest_github_release()
            self.updater_status.setText(
                f"Latest: {cand.version} | auto_install={self.updater.auto_install_enabled} | "
                f"signed={bool(cand.sig_b64)}"
            )
        except Exception as exc:  # noqa: BLE001
            self.updater_status.setText(f"Update check failed: {exc}")

    def shutdown(self) -> None:
        """Clean hook for MainWindow shutdown lifecycle."""
        return

    def apply_theme(self) -> None:
        self.empty_state.apply_theme()

    def retranslate(self) -> None:
        self.set_header(tr("automation.title"), tr("automation.lead"))
        self.tabs.setTabText(0, tr("automation.tab.schedules"))
        self.tabs.setTabText(1, tr("automation.tab.monitoring"))
        self.tabs.setTabText(2, tr("automation.tab.playground"))
        self.tabs.setTabText(3, tr("automation.tab.backup"))
        self.add_sched_btn.setText(tr("automation.sched.add"))
        self.run_sched_btn.setText(tr("automation.sched.run"))
        self.del_sched_btn.setText(tr("automation.sched.delete"))
        self.refresh_sched_btn.setText(tr("automation.sched.refresh"))
        self._sched_hdr.set_texts(tr("automation.sched.table_title"))
        self._hist_hdr.set_texts(tr("automation.sched.history_title"))
        self.empty_state.set_content(tr("automation.sched.empty_title"), tr("automation.sched.empty_desc"))
        self.schedules_table.setHorizontalHeaderLabels([
            tr("automation.col.id"),
            tr("automation.col.name"),
            tr("automation.col.trigger"),
            tr("automation.col.tool"),
            tr("automation.col.tz"),
            tr("automation.col.status"),
        ])
        self._admin_notice_lbl.setText(tr("automation.mon.admin_notice"))
        self.audit_filter_input.setPlaceholderText(tr("automation.mon.audit_filter"))
        self.mon_refresh_btn.setText(tr("automation.mon.refresh"))
        self.mon_export_btn.setText(tr("automation.mon.export"))
        self._snap_hdr.set_texts(tr("automation.mon.snapshot_title"))
        self._audit_hdr.set_texts(tr("automation.mon.audit_title"))
        self._live_warn_lbl.setText(tr("automation.playground.live_warning"))
        self.playground_run_btn.setText(tr("automation.playground.run"))
        self._pg_out_hdr.set_texts(tr("automation.playground.output_title"))
        self._backup_hdr.set_texts(tr("automation.backup.title"), tr("automation.backup.dpapi_notice"))
        self.backup_create_btn.setText(tr("automation.backup.create"))
        self.backup_restore_btn.setText(tr("automation.backup.restore"))
        self._updater_hdr.set_texts(
            tr("automation.updater.title"), tr("automation.updater.notice", version=__version__)
        )
        self.updater_check_btn.setText(tr("automation.updater.check"))
        self._reload_schedules_table()
