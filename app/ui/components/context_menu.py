"""Reusable theme-aware, silent, keyboard-accessible context menus and action buttons."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from PyQt6.QtCore import QPoint, QRect, QSize, Qt
from PyQt6.QtGui import QAction, QColor, QGuiApplication, QPainter, QPaintEvent
from PyQt6.QtWidgets import QMenu, QPushButton, QStyle, QStyleOptionMenuItem, QWidget

from app.ui import icons, theme


@dataclass(frozen=True)
class MenuActionSpec:
    """Declarative menu item descriptor shared across row and toolbar context menus."""

    key: str
    label: str
    callback: Callable[[], object] | None = None
    icon_name: str | None = None
    enabled: bool = True
    danger: bool = False
    separator_before: bool = False
    submenu: tuple["MenuActionSpec", ...] | list["MenuActionSpec"] | None = None
    shortcut: str | None = None


def clamp_menu_pos(menu: QMenu, global_pos: QPoint) -> QPoint:
    """Ensure menu opens completely inside the active monitor's available geometry."""
    screen = QGuiApplication.screenAt(global_pos) or QGuiApplication.primaryScreen()
    if screen is None:
        return global_pos
    avail: QRect = screen.availableGeometry()
    hint = menu.sizeHint()
    x = max(avail.left() + 4, min(global_pos.x(), avail.right() - hint.width() - 4))
    y = max(avail.top() + 4, min(global_pos.y(), avail.bottom() - hint.height() - 4))
    return QPoint(x, y)


class AppContextMenu(QMenu):
    """Minimalist Dark/Light QMenu with vector icons, danger tinting, and silent behavior."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._danger_actions: set[QAction] = set()
        self.setCursor(Qt.CursorShape.ArrowCursor)
        self.apply_theme()

    def apply_theme(self) -> None:
        self.setStyleSheet(
            f"""
            QMenu {{
                background: {theme.ELEVATED};
                color: {theme.TEXT_STRONG};
                border: 1px solid {theme.BORDER_STRONG};
                border-radius: 8px;
                padding: 4px;
            }}
            QMenu::item {{
                padding: 6px 20px 6px 10px;
                border-radius: 5px;
                font-size: 12px;
                color: {theme.TEXT_STRONG};
            }}
            QMenu::item:selected {{
                background: {theme.ACTIVE};
                color: {theme.TEXT_STRONG};
            }}
            QMenu::item:disabled {{
                color: {theme.TEXT_FAINT};
                background: transparent;
            }}
            QMenu::separator {{
                height: 1px;
                background: {theme.HAIRLINE};
                margin: 4px 6px;
            }}
            QMenu::icon {{
                padding-left: 4px;
            }}
            """
        )

    def add_specs(self, specs: list[MenuActionSpec] | tuple[MenuActionSpec, ...]) -> None:
        self._danger_actions.clear()
        for spec in specs:
            if spec.separator_before and not self.isEmpty():
                self.addSeparator()
            if spec.submenu:
                sub = AppContextMenu(self)
                sub.setTitle(spec.label)
                if spec.icon_name:
                    color = theme.TEXT_MUTED if spec.enabled else theme.TEXT_FAINT
                    sub.setIcon(icons.vector_icon(spec.icon_name, color, 14))
                sub.add_specs(spec.submenu)
                sub_act = self.addMenu(sub)
                if sub_act is not None:
                    sub_act.setEnabled(spec.enabled)
                continue

            act = QAction(spec.label, self)
            act.setEnabled(spec.enabled)
            if spec.shortcut:
                act.setShortcut(spec.shortcut)
            if spec.icon_name:
                if not spec.enabled:
                    icon_color = theme.TEXT_FAINT
                elif spec.danger:
                    icon_color = theme.ERR
                else:
                    icon_color = theme.TEXT_MUTED
                act.setIcon(icons.vector_icon(spec.icon_name, icon_color, 14))
            if spec.danger:
                self._danger_actions.add(act)
            if spec.callback is not None and spec.enabled:
                cb = spec.callback
                act.triggered.connect(lambda _checked=False, fn=cb: fn())
            self.addAction(act)

    @classmethod
    def from_specs(
        cls,
        specs: list[MenuActionSpec] | tuple[MenuActionSpec, ...],
        parent: QWidget | None = None,
    ) -> "AppContextMenu":
        menu = cls(parent)
        menu.add_specs(specs)
        return menu

    def exec_clamped(self, global_pos: QPoint) -> QAction | None:
        return self.exec(clamp_menu_pos(self, global_pos))

    def popup_clamped(self, global_pos: QPoint) -> None:
        self.popup(clamp_menu_pos(self, global_pos))

    def paintEvent(self, event: QPaintEvent | None) -> None:  # noqa: N802
        super().paintEvent(event)
        if not self._danger_actions or event is None:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        active = self.activeAction()
        for act in self._danger_actions:
            if not act.isVisible() or not act.isEnabled():
                continue
            rect = self.actionGeometry(act)
            if not rect.isValid():
                continue
            is_selected = act is active
            bg = QColor(theme.ERR_SOFT_BG if is_selected else theme.ELEVATED)
            painter.fillRect(rect.adjusted(2, 1, -2, -1), bg)
            if is_selected:
                painter.setPen(QColor(theme.ERR_SOFT_BORDER))
                painter.drawRoundedRect(rect.adjusted(2, 1, -3, -2), 5, 5)
            opt = QStyleOptionMenuItem()
            self.initStyleOption(opt, act)
            icon_rect = rect.adjusted(10, 0, 0, 0)
            icon_rect.setWidth(14)
            if not act.icon().isNull():
                act.icon().paint(painter, icon_rect, Qt.AlignmentFlag.AlignCenter)
            text_left = 30 if not act.icon().isNull() else 12
            text_rect = rect.adjusted(text_left, 0, -12, 0)
            painter.setPen(QColor(theme.ERR))
            painter.setFont(self.font())
            painter.drawText(
                text_rect,
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft | Qt.TextFlag.TextShowMnemonic,
                act.text(),
            )
            if act.shortcut().toString():
                sc_rect = rect.adjusted(text_left, 0, -10, 0)
                painter.setPen(QColor(theme.TEXT_FAINT))
                painter.drawText(
                    sc_rect,
                    Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                    act.shortcut().toString(QStyle.StandardPixmap.SP_CustomBase if False else None),  # type: ignore[arg-type]
                )
        painter.end()


def make_row_menu_button(tooltip: str = "", parent: QWidget | None = None) -> QPushButton:
    """Compact per-row '⋯' button with standard arrow cursor and centered dot icon."""
    btn = QPushButton("", parent)
    btn.setObjectName("RowMenuBtn")
    btn.setCursor(Qt.CursorShape.ArrowCursor)
    btn.setIcon(icons.vector_icon("more", theme.TEXT_MUTED, 14))
    btn.setIconSize(QSize(14, 14))
    btn.setFixedSize(26, 24)
    if tooltip:
        btn.setToolTip(tooltip)
        btn.setAccessibleName(tooltip)
    return btn


def make_toolbar_menu_button(tooltip: str = "", parent: QWidget | None = None) -> QPushButton:
    """Toolbar overflow '⋯' button using standard arrow cursor."""
    btn = QPushButton("", parent)
    btn.setObjectName("Ghost")
    btn.setCursor(Qt.CursorShape.ArrowCursor)
    btn.setIcon(icons.vector_icon("more", theme.TEXT_STRONG, 15))
    btn.setIconSize(QSize(15, 15))
    btn.setFixedWidth(30)
    if tooltip:
        btn.setToolTip(tooltip)
        btn.setAccessibleName(tooltip)
    return btn
