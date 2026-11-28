"""Explicit owner review & snapshot-bound re-approval dialog for changed Workspace manifests (Stage N04)."""
from __future__ import annotations

from typing import Any

from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.ui.components.cards import Badge, Divider
from app.ui.components.silent_dialog import SilentDialog, SilentMessageBox
from app.ui.i18n import tr
from backend.workspaces.discovery import WizardStalePlanError, redact_discovery_text
from backend.workspaces.manifest_policy import ManifestDriftError, ManifestReapprovalPreview
from backend.workspaces.server_links import WorkspaceServerCoordinator


def _format_manifest_changes(preview: ManifestReapprovalPreview) -> list[str]:
    if not preview.manifest_changes:
        return ["Manifests: unchanged"]
    lines = ["Manifests changed:"]
    for item in preview.manifest_changes:
        old_s = item.old_sha256[:12] if item.old_sha256 else "—"
        new_s = item.new_sha256[:12] if item.new_sha256 else "—"
        detail = f" ({redact_discovery_text(item.detail)})" if item.detail else ""
        lines.append(f"  [{item.status.upper()}] {item.rel_path}: {old_s} -> {new_s}{detail}")
    return lines


def _format_command_and_runtime_lines(preview: ManifestReapprovalPreview) -> list[str]:
    lines: list[str] = []
    if preview.added_commands or preview.changed_commands or preview.unmatched_existing_commands:
        lines.append("Commands:")
        for cname, cmd in sorted(preview.added_commands.items()):
            lines.append(f"  [+] {cname}: {cmd}")
        for cname, (old_c, new_c) in sorted(preview.changed_commands.items()):
            lines.append(f"  [~] {cname}: {old_c}  ==>  {new_c}")
        if preview.unmatched_existing_commands:
            lines.append(f"  [kept] {', '.join(preview.unmatched_existing_commands)}")
    if preview.runtime_changes:
        lines.append("Runtime settings:")
        for key, (old_v, new_v) in sorted(preview.runtime_changes.items()):
            lines.append(f"  {key}: {old_v or '—'} -> {new_v or '—'}")
    return lines


def _format_server_and_permission_lines(preview: ManifestReapprovalPreview) -> list[str]:
    lines: list[str] = []
    if preview.updatable_servers or preview.skipped_servers or preview.server_param_changes:
        lines.append("Linked servers:")
        if preview.updatable_servers:
            lines.append(f"  Digests synced cleanly: {', '.join(preview.updatable_servers)}")
        if preview.skipped_servers:
            lines.append(f"  Untouched (manual/shared/external cwd): {', '.join(preview.skipped_servers)}")
        for sname, diff in sorted(preview.server_param_changes.items()):
            lines.append(f"  [~] {sname}: {diff}")
    if preview.lifecycle_warnings:
        lines.append("Lifecycle hook warnings:")
        for warn in preview.lifecycle_warnings:
            lines.append(f"  [WARN] {warn}")
    perms = preview.effective_permissions
    lines.append(
        "Effective permissions (unchanged): "
        f"read={perms.get('read')}, write={perms.get('write')}, delete={perms.get('delete')}, "
        f"execute={perms.get('execute')}, git={perms.get('git')}, "
        f"allow_oauth_clients={perms.get('allow_oauth_clients')}, oauth_mode={perms.get('oauth_mode')}, "
        f"min_profile={perms.get('min_profile')}, trust_git_hooks={perms.get('trust_git_hooks')}"
    )
    return lines


def format_reapproval_preview_text(preview: ManifestReapprovalPreview) -> str:
    """Render a concise secret-free summary of manifest, command, server, and permission impact."""
    lines = [
        f"Workspace: {preview.workspace_name} ({preview.workspace_id})",
        f"Root: {preview.root_path}",
    ]
    if preview.blocking_errors:
        lines.append("BLOCKING ERRORS:")
        lines.extend(f"  [ERROR] {err}" for err in preview.blocking_errors)
    lines.extend(_format_manifest_changes(preview))
    lines.extend(_format_command_and_runtime_lines(preview))
    lines.extend(_format_server_and_permission_lines(preview))
    return redact_discovery_text("\n".join(lines))


class ManifestReapprovalDialog(SilentDialog):
    """Modal preview & explicit snapshot-bound re-approval dialog for drifted Workspace manifests."""

    def __init__(
        self,
        coordinator: WorkspaceServerCoordinator,
        workspace_id: str,
        *,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._coordinator = coordinator
        self._workspace_id = workspace_id
        self._preview: ManifestReapprovalPreview | None = None
        self.commit_result: dict[str, Any] | None = None

        self.setMinimumSize(620, 440)
        self.resize(720, 500)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        head_row = QHBoxLayout()
        head_row.setSpacing(8)
        self._lead_lbl = QLabel()
        self._lead_lbl.setObjectName("Hint")
        self._lead_lbl.setWordWrap(True)
        self.status_badge = Badge("…", variant="warn")
        head_row.addWidget(self._lead_lbl, 1)
        head_row.addWidget(self.status_badge)
        root.addLayout(head_row)

        self.preview_view = QPlainTextEdit()
        self.preview_view.setObjectName("ConsoleLog")
        self.preview_view.setReadOnly(True)
        root.addWidget(self.preview_view, 1)

        self.apply_commands_check = QCheckBox()
        self.apply_commands_check.setChecked(False)
        self.apply_runtime_check = QCheckBox()
        self.apply_runtime_check.setChecked(False)
        self.apply_servers_check = QCheckBox()
        self.apply_servers_check.setChecked(False)
        for cb in (self.apply_commands_check, self.apply_runtime_check, self.apply_servers_check):
            root.addWidget(cb)

        self._notice_lbl = QLabel()
        self._notice_lbl.setObjectName("Hint")
        self._notice_lbl.setWordWrap(True)
        root.addWidget(self._notice_lbl)

        root.addWidget(Divider())
        footer = QHBoxLayout()
        footer.setSpacing(8)
        self.refresh_btn = QPushButton()
        self.refresh_btn.setObjectName("Ghost")
        self.refresh_btn.clicked.connect(self.refresh_preview)
        self.cancel_btn = QPushButton()
        self.cancel_btn.setObjectName("Ghost")
        self.cancel_btn.clicked.connect(self.reject)
        self.approve_btn = QPushButton()
        self.approve_btn.setObjectName("Accent")
        self.approve_btn.clicked.connect(self.approve)
        footer.addWidget(self.refresh_btn)
        footer.addStretch(1)
        footer.addWidget(self.cancel_btn)
        footer.addWidget(self.approve_btn)
        root.addLayout(footer)

        self.retranslate()
        self.refresh_preview()

    def retranslate(self) -> None:
        self.setWindowTitle(tr("workspaces.reapprove.title"))
        ws_label = self._preview.workspace_name if self._preview else self._workspace_id
        self._lead_lbl.setText(tr("workspaces.reapprove.lead", name=ws_label))
        self.apply_commands_check.setText(tr("workspaces.reapprove.apply_commands"))
        self.apply_runtime_check.setText(tr("workspaces.reapprove.apply_runtime"))
        self.apply_servers_check.setText(tr("workspaces.reapprove.apply_servers"))
        self.refresh_btn.setText(tr("workspaces.reapprove.refresh"))
        self.cancel_btn.setText(tr("common.cancel"))
        self.approve_btn.setText(tr("workspaces.reapprove.approve"))

    def _sync_apply_checkboxes(self, preview: ManifestReapprovalPreview) -> None:
        blocked = bool(preview.blocking_errors)
        pairs = (
            (self.apply_commands_check, bool(preview.added_commands or preview.changed_commands)),
            (self.apply_runtime_check, bool(preview.runtime_changes)),
            (self.apply_servers_check, bool(preview.server_param_changes)),
        )
        for cb, has_updates in pairs:
            cb.setEnabled(has_updates and not blocked)
            if not has_updates:
                cb.setChecked(False)

    def refresh_preview(self) -> None:
        try:
            preview = self._coordinator.prepare_manifest_reapproval(self._workspace_id)
        except Exception as exc:  # noqa: BLE001
            self._preview = None
            self.preview_view.setPlainText(redact_discovery_text(str(exc)))
            self.status_badge.setText("error")
            self.status_badge.set_variant("err")
            self.approve_btn.setEnabled(False)
            self._notice_lbl.setText(redact_discovery_text(str(exc)))
            return

        self._preview = preview
        self._lead_lbl.setText(tr("workspaces.reapprove.lead", name=preview.workspace_name))
        self.preview_view.setPlainText(format_reapproval_preview_text(preview))
        self._sync_apply_checkboxes(preview)

        if preview.blocking_errors:
            self.status_badge.setText("blocked")
            self.status_badge.set_variant("err")
            self._notice_lbl.setText(tr("workspaces.reapprove.blocked"))
            self.approve_btn.setEnabled(False)
            return
        count = len(preview.manifest_changes)
        self.status_badge.setText(f"{count} Δ" if count else "OK")
        self.status_badge.set_variant("warn" if count else "ok")
        self._notice_lbl.setText("" if preview.has_changes else tr("workspaces.reapprove.none"))
        self.approve_btn.setEnabled(preview.snapshot is not None)

    def approve(self) -> None:
        if self._preview is None or self._preview.snapshot is None or self._preview.blocking_errors:
            return
        self.approve_btn.setEnabled(False)
        try:
            self.commit_result = self._coordinator.commit_manifest_reapproval(
                self._workspace_id,
                expected_snapshot=self._preview.snapshot,
                apply_command_updates=self.apply_commands_check.isChecked(),
                apply_runtime_updates=self.apply_runtime_check.isChecked(),
                apply_server_updates=self.apply_servers_check.isChecked(),
            )
            self.accept()
        except (WizardStalePlanError, ManifestDriftError):
            self.refresh_preview()
            self._notice_lbl.setText(tr("workspaces.reapprove.stale"))
            SilentMessageBox.warning(
                self,
                tr("workspaces.reapprove.title"),
                tr("workspaces.reapprove.stale"),
            )
        except Exception as exc:  # noqa: BLE001
            self.refresh_preview()
            SilentMessageBox.warning(
                self,
                tr("workspaces.reapprove.title"),
                redact_discovery_text(str(exc)),
            )
