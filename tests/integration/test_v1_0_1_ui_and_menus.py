"""GUI & integration verification for v1.0.1: cursors, ClientsPage alignment, context menus, purge, SafeSpinBox."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QPoint, QPointF, Qt
from PyQt6.QtGui import QWheelEvent
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QLabel,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QWidget,
)
from mcp.shared.auth import OAuthClientInformationFull

from app.config import Settings
from app.core.service_manager import ServiceManager
from app.ui import theme
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.components.context_menu import AppContextMenu, MenuActionSpec, clamp_menu_pos
from app.ui.components.safe_spin import SafeDoubleSpinBox, SafeSpinBox
from app.ui.components.silent_dialog import SilentMessageBox
from app.ui.components.table import TableCellCombo
from app.ui.components.toggle_switch import ToggleSwitch
from app.ui.gateway_add_wizard import AddMcpServerWizard
from app.ui.main_window import MainWindow
from app.ui.oauth_clients_dialog import OAuthClientsDialog
from app.ui.pages.automation_page import AutomationPage
from app.ui.pages.clients_page import ClientsPage
from app.ui.pages.devices_page import DevicesPage
from app.ui.pages.extensions_page import ExtensionsPage
from app.ui.pages.gateway_page import GatewayPage
from app.ui.pages.servers_page import RenameServerDialog, ServerProfileDialog, ServersPage, TemplateWizardDialog
from app.ui.pages.tasks_page import TasksPage
from app.ui.pages.workspaces_page import WorkspacesPage
from backend.oauth_execution import ExecutionApprovals
from backend.oauth_store import OAuthStore


def _get_app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app  # type: ignore[return-value]


class V101UiAndMenuTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = _get_app()
        theme.apply(cls.app, theme.THEME_DARK)
        i18n.set_language(LANG_RU)

    def tearDown(self) -> None:
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)

    def test_no_pointing_hand_cursor_on_standard_controls_and_spinboxes_ignore_wheel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("app.paths.user_data_dir", return_value=root), patch(
                "app.core.service_manager.user_data_dir", return_value=root
            ), patch("app.core.domain_state.user_data_dir", return_value=root), patch(
                "app.config.user_data_dir", return_value=root
            ), patch("app.ui.theme.user_data_dir", return_value=root, create=True), patch(
                "app.ui.main_window.default_store_path", return_value=root / "oauth" / "state.sqlite3"
            ):
                settings = Settings()
                mgr = ServiceManager(settings)
                win = MainWindow(mgr, settings, tray_available=False)
                try:
                    win.resize(1280, 820)
                    win.show()
                    self.app.processEvents()

                    dialogs: list[QWidget] = [
                        AddMcpServerWizard(win.gateway_page.store, parent=win),
                        ServerProfileDialog(win.workspaces_page.server_store, is_new=True, parent=win),
                        TemplateWizardDialog(win.workspaces_page.server_store, parent=win),
                        RenameServerDialog("old_srv", {"old_srv"}, parent=win),
                    ]
                    roots: list[QWidget] = [win, *dialogs]

                    spin_count = 0
                    for root_w in roots:
                        for w in root_w.findChildren(QWidget):
                            # No QDoubleSpinBox/QSpinBox outside SafeSpinBox/SafeDoubleSpinBox
                            if isinstance(w, QSpinBox) and not isinstance(w, SafeSpinBox):
                                self.fail(f"Found raw QSpinBox: {w!r} in {root_w!r}")
                            if isinstance(w, QDoubleSpinBox) and not isinstance(w, SafeDoubleSpinBox):
                                self.fail(f"Found raw QDoubleSpinBox: {w!r} in {root_w!r}")
                            if isinstance(w, (SafeSpinBox, SafeDoubleSpinBox)):
                                spin_count += 1
                                before = w.value()
                                w.setFocus()
                                wheel = QWheelEvent(
                                    QPointF(5, 5),
                                    QPointF(5, 5),
                                    QPoint(0, 120),
                                    QPoint(0, 120),
                                    Qt.MouseButton.NoButton,
                                    Qt.KeyboardModifier.NoModifier,
                                    Qt.ScrollPhase.NoScrollPhase,
                                    False,
                                )
                                QApplication.sendEvent(w, wheel)
                                self.assertFalse(wheel.isAccepted())
                                self.assertEqual(w.value(), before)

                            # Standard interactive/display widgets must NOT carry PointingHandCursor
                            if isinstance(w, QPushButton):
                                if w.objectName() in ("Link", "SubtleLink"):
                                    continue
                                self.assertNotEqual(w.cursor().shape(), Qt.CursorShape.PointingHandCursor, repr(w))
                            elif isinstance(
                                w,
                                (QComboBox, ToggleSwitch, QCheckBox, QTableWidget, SafeSpinBox, SafeDoubleSpinBox, QLabel),
                            ):
                                self.assertNotEqual(w.cursor().shape(), Qt.CursorShape.PointingHandCursor, repr(w))

                    self.assertGreaterEqual(spin_count, 5)
                    for d in dialogs:
                        d.close()
                finally:
                    win.allow_close()
                    win.close()

    def test_clients_page_inline_combo_alignment_scaling_and_row_context_menu(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_path = root / "oauth.sqlite3"
            store = OAuthStore(store_path, "https://srv.example.com", "https://srv.example.com/mcp")
            store.bind_owner("owner-tok")
            execution = ExecutionApprovals(store)
            for cid, name in (("cid_alpha", "Claude Code"), ("cid_beta", "ChatGPT")):
                store.save_client(
                    OAuthClientInformationFull(
                        client_id=cid,
                        client_secret="s" * 24,
                        client_name=name,
                        redirect_uris=["https://example.com/cb"],
                        grant_types=["authorization_code", "refresh_token"],
                        response_types=["code"],
                    )
                )
                store.mark_approved(cid)
            execution.set_client_profile("cid_beta", "allowlist")

            page = ClientsPage(store_path_fn=lambda: store_path)
            try:
                page.set_public_url("https://srv.example.com/mcp")
                page.resize(1024, 680)
                page.show()
                self.app.processEvents()

                # Toolbar revoke button must not exist anymore; actions live in row context menu
                self.assertFalse(hasattr(page, "revoke_button"))
                self.assertEqual(page.table.columnCount(), 5)
                self.assertEqual(page.table.rowCount(), 2)

                # Combo fits cleanly centered inside its row across languages & larger DPI fonts
                for lang in (LANG_RU, LANG_EN):
                    i18n.set_language(lang)
                    page.retranslate()
                    for pt in (10, 14):
                        f = page.font()
                        f.setPointSize(pt)
                        page.table.setFont(f)
                        page.reload()
                        self.app.processEvents()
                        holder = page.table.cellWidget(0, 2)
                        self.assertIsInstance(holder, TableCellCombo)
                        assert isinstance(holder, TableCellCombo)
                        self.assertGreaterEqual(page.table.rowHeight(0), holder.combo.sizeHint().height())
                        self.assertGreaterEqual(page.table.columnWidth(2), holder.minimumSizeHint().width())

                # Verify row context menu operates on target row (row for cid_beta), even if the other row is selected!
                row_beta = next(i for i, e in enumerate(page._entries) if e["client_id"] == "cid_beta")
                row_alpha = 1 - row_beta
                page.table.selectRow(row_alpha)
                specs_beta = page._build_row_menu(row_beta)
                by_key = {s.key: s for s in specs_beta}
                self.assertIn("copy_id", by_key)
                self.assertIn("details", by_key)
                self.assertIn("revoke", by_key)
                self.assertTrue(by_key["revoke"].danger)
                self.assertTrue(by_key["reset_custom"].enabled)

                by_key["copy_id"].callback()  # type: ignore[misc]
                self.assertEqual(QApplication.clipboard().text(), "cid_beta")

                # Resetting custom overrides via menu clears cid_beta's override cleanly
                by_key["reset_custom"].callback()  # type: ignore[misc]
                self.assertNotIn("cid_beta", execution.client_profiles())

                # Revoking target row via confirmed menu callback revokes cid_beta (not selected cid_alpha!)
                with patch(
                    "app.ui.pages.clients_page.SilentMessageBox.question",
                    return_value=SilentMessageBox.StandardButton.Yes,
                ):
                    specs_beta = page._build_row_menu(row_beta)
                    next(s for s in specs_beta if s.key == "revoke").callback()  # type: ignore[misc]
                self.assertIsNotNone(store.get_client("cid_alpha"))
                self.assertIsNone(store.get_client("cid_beta"))

                # OAuthClientsDialog uses same alignment helper
                with patch("app.ui.oauth_clients_dialog.default_store_path", return_value=store_path):
                    dlg = OAuthClientsDialog("https://srv.example.com/mcp")
                    self.assertEqual(dlg.table.rowCount(), 1)
                    self.assertIsInstance(dlg.table.cellWidget(0, 2), TableCellCombo)
                    dlg.close()
            finally:
                page.close()

    def test_tasks_page_and_other_pages_context_menus_and_purge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            from backend.tasks import TaskSpec, TaskStore

            store = TaskStore(root / "tasks.sqlite3")
            rec_done, _ = store.create_task(
                spec=TaskSpec(kind="windows", command="echo ok"),
                owner_client_id="owner",
                profile="allowlist",
                title="done-task",
            )
            store.mark_finished(rec_done.task_id, status="succeeded")
            rec_live, _ = store.create_task(
                spec=TaskSpec(kind="windows", command="echo live"),
                owner_client_id="owner",
                profile="allowlist",
                title="live-task",
            )
            with store._db() as db:
                db.execute("UPDATE tasks SET status='running', started_at=10.0 WHERE task_id=?", (rec_live.task_id,))

            tpage = TasksPage(
                db_path=root / "tasks.sqlite3",
                spool_dir=root / "spool",
                artifacts_dir=root / "art",
            )
            try:
                tpage.reload()
                self.assertEqual(tpage.table.rowCount(), 2)
                rows = {tid: idx for idx, tid in enumerate(tpage._row_task_ids)}
                done_specs = {s.key: s for s in tpage._build_row_menu(rows[rec_done.task_id])}
                live_specs = {s.key: s for s in tpage._build_row_menu(rows[rec_live.task_id])}
                self.assertTrue(done_specs["delete"].enabled)
                self.assertFalse(live_specs["delete"].enabled)
                self.assertTrue(live_specs["stop"].enabled)

                with patch("app.ui.pages.tasks_page.SilentMessageBox.question") as q_mock:
                    q_mock.return_value = SilentMessageBox.StandardButton.Yes
                    tpage.purge_old_tasks(older_than_days=None)
                self.assertIsNone(store.get_task(rec_done.task_id))
                self.assertIsNotNone(store.get_task(rec_live.task_id))
            finally:
                tpage.close()

            # All other pages instantiate cleanly and expose row menu providers without hand cursor
            for page_cls, kwargs in (
                (GatewayPage, {"config_path": root / "gw.json"}),
                (ServersPage, {"config_path": root / "srv.json", "secrets_dir": root / "srv_sec"}),
                (
                    WorkspacesPage,
                    {"config_path": root / "ws.json", "history_dir": root / "ws_h", "secrets_dir": root / "ws_s"},
                ),
                (DevicesPage, {"config_path": root / "dev.json", "secrets_dir": root / "dev_s"}),
                (ExtensionsPage, {"extensions_dir": root / "ext", "secret_store": None}),
                (AutomationPage, {"automation_dir": root / "auto", "config_root": root}),
            ):
                p = page_cls(**kwargs)  # type: ignore[arg-type]
                try:
                    self.assertIsNotNone(p)
                finally:
                    if hasattr(p, "shutdown"):
                        p.shutdown()
                    p.close()

            # AppContextMenu + clamp_menu_pos keyboard/screen clamping check
            menu = AppContextMenu.from_specs([MenuActionSpec(key="k", label="Item", icon_name="copy")])
            self.assertEqual(len(menu.actions()), 1)
            pt = clamp_menu_pos(menu, QPoint(999999, 999999))
            self.assertLess(pt.x(), 999999)
            self.assertLess(pt.y(), 999999)
            menu.close()


if __name__ == "__main__":
    unittest.main()
