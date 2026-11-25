"""ThemeManager (Dark / Light / System) and QSS styling in Linear + Docker Desktop style."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from string import Template

from PyQt6.QtCore import QObject, QPointF, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QGuiApplication, QImage, QPainter, QPalette, QPen
from PyQt6.QtWidgets import QApplication, QStyleFactory, QWidget

from app.ui import tokens as tok
from app.ui.i18n import tr

THEME_SYSTEM = "system"
THEME_DARK = "dark"
THEME_LIGHT = "light"
THEME_MODES = (THEME_SYSTEM, THEME_DARK, THEME_LIGHT)

# Dynamic active color tokens synced on every theme switch for backwards-compatible imports.
BG = tok.DARK_TOKENS.bg
SIDEBAR = tok.DARK_TOKENS.sidebar
SURFACE = tok.DARK_TOKENS.surface
ELEVATED = tok.DARK_TOKENS.elevated
CONTROL = tok.DARK_TOKENS.control
CONTROL_HOVER = tok.DARK_TOKENS.control_hover
ACTIVE = tok.DARK_TOKENS.active
INPUT = tok.DARK_TOKENS.input
HAIRLINE = tok.DARK_TOKENS.hairline
BORDER = tok.DARK_TOKENS.border
BORDER_STRONG = tok.DARK_TOKENS.border_strong
TEXT_STRONG = tok.DARK_TOKENS.text_strong
TEXT = tok.DARK_TOKENS.text
TEXT_MUTED = tok.DARK_TOKENS.text_muted
TEXT_FAINT = tok.DARK_TOKENS.text_faint
ACCENT = tok.DARK_TOKENS.accent
ACCENT_HOVER = tok.DARK_TOKENS.accent_hover
ACCENT_STRONG = tok.DARK_TOKENS.accent_strong
ACCENT_PRESSED = tok.DARK_TOKENS.accent_pressed
ACCENT_TEXT = tok.DARK_TOKENS.accent_text
ACCENT_SOFT_BG = tok.DARK_TOKENS.accent_soft_bg
ACCENT_SOFT_BORDER = tok.DARK_TOKENS.accent_soft_border
LINK = tok.DARK_TOKENS.link
OK = tok.DARK_TOKENS.ok
OK_SOFT_BG = tok.DARK_TOKENS.ok_soft_bg
OK_SOFT_BORDER = tok.DARK_TOKENS.ok_soft_border
WARN = tok.DARK_TOKENS.warn
WARN_SOFT_BG = tok.DARK_TOKENS.warn_soft_bg
WARN_SOFT_BORDER = tok.DARK_TOKENS.warn_soft_border
ERR = tok.DARK_TOKENS.err
ERR_SOFT_BG = tok.DARK_TOKENS.err_soft_bg
ERR_SOFT_BORDER = tok.DARK_TOKENS.err_soft_border
IDLE = tok.DARK_TOKENS.idle

PENDING = {"starting", "degraded", "stopping"}
SERIF_FAMILIES = list(tok.SANS_FAMILIES)
SANS_FAMILIES = list(tok.SANS_FAMILIES)
FONT_SERIF = tok.FONT_UI
FONT_UI = tok.FONT_UI
FONT_MONO = tok.FONT_MONO

OVERALL: dict[str, tuple[str, str]] = {}
SERVICE: dict[str, tuple[str, str]] = {}
LOG_SOURCES: dict[str, tuple[str, str]] = {}


def _sync_globals(active: tok.ThemeTokens) -> None:
    global BG, SIDEBAR, SURFACE, ELEVATED, CONTROL, CONTROL_HOVER, ACTIVE, INPUT
    global HAIRLINE, BORDER, BORDER_STRONG, TEXT_STRONG, TEXT, TEXT_MUTED, TEXT_FAINT
    global ACCENT, ACCENT_HOVER, ACCENT_STRONG, ACCENT_PRESSED, ACCENT_TEXT
    global ACCENT_SOFT_BG, ACCENT_SOFT_BORDER, LINK
    global OK, OK_SOFT_BG, OK_SOFT_BORDER, WARN, WARN_SOFT_BG, WARN_SOFT_BORDER
    global ERR, ERR_SOFT_BG, ERR_SOFT_BORDER, IDLE
    global OVERALL, SERVICE, LOG_SOURCES

    BG = active.bg
    SIDEBAR = active.sidebar
    SURFACE = active.surface
    ELEVATED = active.elevated
    CONTROL = active.control
    CONTROL_HOVER = active.control_hover
    ACTIVE = active.active
    INPUT = active.input
    HAIRLINE = active.hairline
    BORDER = active.border
    BORDER_STRONG = active.border_strong
    TEXT_STRONG = active.text_strong
    TEXT = active.text
    TEXT_MUTED = active.text_muted
    TEXT_FAINT = active.text_faint
    ACCENT = active.accent
    ACCENT_HOVER = active.accent_hover
    ACCENT_STRONG = active.accent_strong
    ACCENT_PRESSED = active.accent_pressed
    ACCENT_TEXT = active.accent_text
    ACCENT_SOFT_BG = active.accent_soft_bg
    ACCENT_SOFT_BORDER = active.accent_soft_border
    LINK = active.link
    OK = active.ok
    OK_SOFT_BG = active.ok_soft_bg
    OK_SOFT_BORDER = active.ok_soft_border
    WARN = active.warn
    WARN_SOFT_BG = active.warn_soft_bg
    WARN_SOFT_BORDER = active.warn_soft_border
    ERR = active.err
    ERR_SOFT_BG = active.err_soft_bg
    ERR_SOFT_BORDER = active.err_soft_border
    IDLE = active.idle

    OVERALL = {
        "stopped": (tr("status.overall.stopped"), IDLE),
        "starting": (tr("status.overall.starting"), WARN),
        "running": (tr("status.overall.running"), OK),
        "degraded": (tr("status.overall.degraded"), WARN),
        "stopping": (tr("status.overall.stopping"), WARN),
        "error": (tr("status.overall.error"), ERR),
    }
    SERVICE = {
        "stopped": (tr("status.service.stopped"), IDLE),
        "starting": (tr("status.service.starting"), WARN),
        "running": (tr("status.service.running"), OK),
        "stopping": (tr("status.service.stopping"), WARN),
        "failed": (tr("status.service.failed"), ERR),
    }
    LOG_SOURCES = {
        "server": ("server", LINK),
        "tunnel": ("tunnel", OK),
        "app": ("app", TEXT_MUTED),
    }


_sync_globals(tok.DARK_TOKENS)


def overall_label_color(state: str) -> tuple[str, str]:
    color = {
        "stopped": IDLE,
        "starting": WARN,
        "running": OK,
        "degraded": WARN,
        "stopping": WARN,
        "error": ERR,
    }.get(state, IDLE)
    return tr(f"status.overall.{state}"), color


def service_label_color(state: str) -> tuple[str, str]:
    color = {
        "stopped": IDLE,
        "starting": WARN,
        "running": OK,
        "stopping": WARN,
        "failed": ERR,
    }.get(state, IDLE)
    return tr(f"status.service.{state}"), color


def detect_system_theme() -> str:
    """Detect Windows/Qt system theme preference (`dark` or `light`)."""
    if sys.platform == "win32":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            ) as key:
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                return THEME_LIGHT if int(value) == 1 else THEME_DARK
        except OSError:
            pass
    app = QGuiApplication.instance()
    if app is not None:
        try:
            scheme = app.styleHints().colorScheme()
            if scheme == Qt.ColorScheme.Light:
                return THEME_LIGHT
            if scheme == Qt.ColorScheme.Dark:
                return THEME_DARK
        except AttributeError:
            pass
    return THEME_DARK


def resolve_tokens(mode: str) -> tuple[str, tok.ThemeTokens]:
    resolved = detect_system_theme() if mode == THEME_SYSTEM else (
        THEME_LIGHT if mode == THEME_LIGHT else THEME_DARK
    )
    return resolved, (tok.LIGHT_TOKENS if resolved == THEME_LIGHT else tok.DARK_TOKENS)


def _build_qss() -> Template:
    return Template("""
* { outline: none; }
QWidget { color: $TEXT; font-family: $FONT_UI; font-size: 13px; }
QMainWindow, QDialog, QWidget#Canvas { background: $BG; }
QScrollArea#Page, QScrollArea#Page > QWidget, QScrollArea#Page > QWidget > QWidget {
    background: $BG;
    border: none;
}
QScrollArea#NavScroll, QScrollArea#NavScroll > QWidget, QScrollArea#NavScroll > QWidget > QWidget {
    background: transparent;
    border: none;
}

/* ---------- sidebar & topbar ---------- */
QFrame#Sidebar {
    background: $SIDEBAR;
    border: none;
    border-right: 1px solid $HAIRLINE;
}
QFrame#TopBar {
    background: $BG;
    border: none;
    border-bottom: 1px solid $HAIRLINE;
}
QLabel#TopBarTitle {
    color: $TEXT_STRONG;
    font-size: 13px;
    font-weight: 600;
}
QLabel#Wordmark {
    color: $TEXT_STRONG;
    font-size: 15px;
    font-weight: 700;
}
QLabel#SidebarSection {
    color: $TEXT_FAINT;
    font-size: 10px;
    font-weight: 700;
    padding: 6px 8px 2px 8px;
}
QLabel#Version {
    color: $TEXT_FAINT;
    font-size: 11px;
    padding: 0 6px;
}
QPushButton#Nav {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 7px;
    padding: 6px 10px;
    text-align: left;
    color: $TEXT_MUTED;
    font-weight: 500;
    font-size: 13px;
}
QPushButton#Nav:hover {
    background: $CONTROL;
    color: $TEXT_STRONG;
}
QPushButton#Nav:checked {
    background: $ACTIVE;
    border-color: $HAIRLINE;
    color: $TEXT_STRONG;
    font-weight: 600;
}
QPushButton#Nav[collapsed="true"] {
    padding: 6px 4px;
    text-align: center;
}
QFrame#StatusChip {
    background: $BG;
    border: 1px solid $HAIRLINE;
    border-radius: 8px;
}
QLabel#ChipText { font-size: 12px; font-weight: 600; }
QLabel#ChipDetail { color: $TEXT_FAINT; font-size: 11px; }

QPushButton#PaletteTrigger {
    background: $INPUT;
    color: $TEXT_MUTED;
    border: 1px solid $BORDER;
    border-radius: 7px;
    padding: 5px 10px;
    text-align: left;
    font-weight: 500;
    font-size: 12px;
}
QPushButton#PaletteTrigger:hover {
    border-color: $BORDER_STRONG;
    color: $TEXT_STRONG;
}

/* ---------- typography ---------- */
QLabel#PageTitle {
    color: $TEXT_STRONG;
    font-size: 22px;
    font-weight: 700;
}
QLabel#PageLead { color: $TEXT_MUTED; font-size: 13px; }
QLabel#SectionTitle { color: $TEXT_STRONG; font-size: 14px; font-weight: 600; }
QLabel#FieldLabel { color: $TEXT_MUTED; font-size: 12px; font-weight: 600; }
QLabel#Hint { color: $TEXT_FAINT; font-size: 12px; }
QLabel#Error { color: $ERR; font-size: 12px; font-weight: 500; }
QLabel#Mono { font-family: $FONT_MONO; font-size: 12px; color: $TEXT_STRONG; }
QLabel#ServiceName { color: $TEXT_STRONG; font-weight: 600; font-size: 13px; }
QLabel#ServiceDetail { color: $TEXT_FAINT; font-size: 12px; font-family: $FONT_MONO; }
QLabel#ServiceState { font-size: 12px; font-weight: 600; }

/* ---------- badges & pills ---------- */
QLabel#Badge {
    background: $ERR_SOFT_BG;
    color: $ERR;
    border: 1px solid $ERR_SOFT_BORDER;
    border-radius: 6px;
    padding: 1px 6px;
    font-size: 11px;
    font-weight: 600;
}
QLabel#Pill {
    background: $CONTROL;
    color: $TEXT_MUTED;
    border: 1px solid $BORDER;
    border-radius: 6px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 600;
}
QLabel#Pill[variant="accent"] {
    background: $ACCENT_SOFT_BG;
    color: $ACCENT;
    border-color: $ACCENT_SOFT_BORDER;
}
QLabel#Pill[variant="ok"] {
    background: $OK_SOFT_BG;
    color: $OK;
    border-color: $OK_SOFT_BORDER;
}
QLabel#Pill[variant="warn"] {
    background: $WARN_SOFT_BG;
    color: $WARN;
    border-color: $WARN_SOFT_BORDER;
}
QLabel#Pill[variant="err"] {
    background: $ERR_SOFT_BG;
    color: $ERR;
    border-color: $ERR_SOFT_BORDER;
}

/* ---------- cards & banners ---------- */
QFrame#Card {
    background: $SURFACE;
    border: 1px solid $HAIRLINE;
    border-radius: 10px;
}
QFrame#Elevated {
    background: $ELEVATED;
    border: 1px solid $BORDER;
    border-radius: 10px;
}
QFrame#EmptyState {
    background: $SURFACE;
    border: 1px dashed $BORDER_STRONG;
    border-radius: 10px;
}
QFrame#ErrorBanner {
    background: $ERR_SOFT_BG;
    border: 1px solid $ERR_SOFT_BORDER;
    border-radius: 8px;
}
QFrame#Toast {
    background: $ELEVATED;
    border: 1px solid $BORDER_STRONG;
    border-radius: 8px;
}
QFrame#Toast[variant="ok"] { border-color: $OK_SOFT_BORDER; }
QFrame#Toast[variant="warn"] { border-color: $WARN_SOFT_BORDER; }
QFrame#Toast[variant="err"] { border-color: $ERR_SOFT_BORDER; }
QFrame#PaletteCard {
    background: $ELEVATED;
    border: 1px solid $BORDER_STRONG;
    border-radius: 10px;
}
QFrame#Divider {
    background: $HAIRLINE;
    border: none;
    max-height: 1px;
    min-height: 1px;
}

/* ---------- buttons ---------- */
QPushButton {
    background: $CONTROL;
    color: $TEXT_STRONG;
    border: 1px solid $BORDER;
    border-radius: 7px;
    padding: 6px 13px;
    font-weight: 600;
    font-size: 12px;
}
QPushButton:hover {
    background: $CONTROL_HOVER;
    border-color: $BORDER_STRONG;
}
QPushButton:pressed { background: $ACTIVE; }
QPushButton:focus { border-color: $ACCENT; }
QPushButton:disabled {
    color: $TEXT_FAINT;
    background: $SURFACE;
    border-color: $HAIRLINE;
}

QPushButton#Primary {
    background: $ACCENT_STRONG;
    color: $ACCENT_TEXT;
    border: 1px solid $ACCENT_STRONG;
    border-radius: 8px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
}
QPushButton#Primary:hover {
    background: $ACCENT_HOVER;
    border-color: $ACCENT_HOVER;
}
QPushButton#Primary:pressed {
    background: $ACCENT_PRESSED;
    border-color: $ACCENT_PRESSED;
}
QPushButton#Primary:disabled {
    background: $CONTROL;
    border-color: $HAIRLINE;
    color: $TEXT_FAINT;
}
QPushButton#Primary[running="true"] {
    background: $CONTROL;
    color: $TEXT_STRONG;
    border: 1px solid $BORDER_STRONG;
}
QPushButton#Primary[running="true"]:hover {
    background: $ERR_SOFT_BG;
    border-color: $ERR_SOFT_BORDER;
    color: $ERR;
}

QPushButton#Accent {
    background: $ACCENT_STRONG;
    color: $ACCENT_TEXT;
    border: 1px solid $ACCENT_STRONG;
}
QPushButton#Accent:hover {
    background: $ACCENT_HOVER;
    border-color: $ACCENT_HOVER;
}
QPushButton#Accent:pressed {
    background: $ACCENT_PRESSED;
    border-color: $ACCENT_PRESSED;
}
QPushButton#Accent:disabled {
    background: $CONTROL;
    border-color: $HAIRLINE;
    color: $TEXT_FAINT;
}

QPushButton#Danger {
    background: $ERR_SOFT_BG;
    color: $ERR;
    border: 1px solid $ERR_SOFT_BORDER;
}
QPushButton#Danger:hover {
    border-color: $ERR;
}
QPushButton#Danger:disabled {
    background: $SURFACE;
    border-color: $HAIRLINE;
    color: $TEXT_FAINT;
}

QPushButton#Ghost {
    background: transparent;
    border: 1px solid transparent;
    color: $TEXT_MUTED;
    padding: 6px 10px;
}
QPushButton#Ghost:hover {
    color: $TEXT_STRONG;
    background: $CONTROL;
}
QPushButton#Ghost:disabled {
    color: $TEXT_FAINT;
    background: transparent;
}

QPushButton#Link {
    background: transparent;
    border: none;
    color: $LINK;
    padding: 2px 0;
    font-weight: 500;
    text-align: left;
}
QPushButton#Link:hover {
    text-decoration: underline;
}

QFrame#SegmentGroup {
    background: $INPUT;
    border: 1px solid $BORDER;
    border-radius: 8px;
}
QPushButton#Segment {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 5px 12px;
    color: $TEXT_MUTED;
    font-weight: 500;
}
QPushButton#Segment:hover { color: $TEXT_STRONG; }
QPushButton#Segment:checked {
    background: $ACTIVE;
    border-color: $BORDER;
    color: $TEXT_STRONG;
    font-weight: 600;
}

QPushButton#FilterPill {
    background: transparent;
    border: 1px solid $BORDER;
    border-radius: 6px;
    padding: 4px 10px;
    color: $TEXT_MUTED;
    font-size: 12px;
    font-weight: 500;
}
QPushButton#FilterPill:hover {
    background: $CONTROL;
    color: $TEXT_STRONG;
}
QPushButton#FilterPill:checked {
    background: $ACCENT_SOFT_BG;
    border-color: $ACCENT_SOFT_BORDER;
    color: $ACCENT;
    font-weight: 600;
}

/* ---------- inputs & combos ---------- */
QLineEdit, QTextEdit, QPlainTextEdit {
    background: $INPUT;
    color: $TEXT_STRONG;
    border: 1px solid $BORDER;
    border-radius: 7px;
    padding: 7px 10px;
    font-size: 12px;
    selection-background-color: $ACCENT_STRONG;
    selection-color: #ffffff;
}
QLineEdit { font-family: $FONT_MONO; }
QLineEdit#UiInput { font-family: $FONT_UI; font-size: 13px; }
QLineEdit:hover, QTextEdit:hover, QPlainTextEdit:hover { border-color: $BORDER_STRONG; }
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus { border-color: $ACCENT; }
QLineEdit:read-only { color: $TEXT_MUTED; }
QLineEdit[invalid="true"] { border-color: $ERR; }

QComboBox {
    background: $INPUT;
    color: $TEXT_STRONG;
    border: 1px solid $BORDER;
    border-radius: 7px;
    padding: 6px 28px 6px 10px;
    font-size: 12px;
    font-weight: 500;
}
QComboBox:hover { border-color: $BORDER_STRONG; }
QComboBox:focus, QComboBox:on { border-color: $ACCENT; }
QComboBox:disabled { color: $TEXT_FAINT; background: $SURFACE; border-color: $HAIRLINE; }
QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 24px;
    border: none;
}
QComboBox::down-arrow {
    image: url("$CHEVRON_DOWN");
    width: 12px;
    height: 12px;
}
QComboBox QAbstractItemView {
    background: $ELEVATED;
    color: $TEXT_STRONG;
    border: 1px solid $BORDER_STRONG;
    border-radius: 7px;
    padding: 4px;
    selection-background-color: $ACTIVE;
    selection-color: $TEXT_STRONG;
}

/* ---------- tables & lists ---------- */
QTableWidget {
    background: $SURFACE;
    color: $TEXT;
    border: 1px solid $HAIRLINE;
    border-radius: 8px;
    gridline-color: $HAIRLINE;
    selection-background-color: $ACTIVE;
    selection-color: $TEXT_STRONG;
}
QTableWidget::item {
    padding: 6px 10px;
    border-bottom: 1px solid $HAIRLINE;
}
QTableWidget::item:selected {
    background: $ACTIVE;
    color: $TEXT_STRONG;
}
QHeaderView::section {
    background: $BG;
    color: $TEXT_MUTED;
    border: none;
    border-bottom: 1px solid $BORDER;
    padding: 7px 10px;
    font-size: 11px;
    font-weight: 600;
    text-align: left;
}
QListWidget {
    background: transparent;
    border: none;
    color: $TEXT;
}
QListWidget::item {
    border-radius: 7px;
    padding: 8px 10px;
    margin: 2px 0;
}
QListWidget::item:hover { background: $CONTROL; }
QListWidget::item:selected {
    background: $ACTIVE;
    color: $TEXT_STRONG;
}

/* ---------- toggles ---------- */
QCheckBox { spacing: 10px; padding: 4px 0; color: $TEXT; }
QCheckBox:disabled { color: $TEXT_FAINT; }
QCheckBox::indicator { width: 32px; height: 18px; image: url("$TOGGLE_OFF"); }
QCheckBox::indicator:checked { image: url("$TOGGLE_ON"); }
QCheckBox::indicator:disabled { image: url("$TOGGLE_OFF_DISABLED"); }
QCheckBox::indicator:checked:disabled { image: url("$TOGGLE_ON_DISABLED"); }

/* ---------- log viewer ---------- */
QPlainTextEdit#Log {
    background: $INPUT;
    color: $TEXT_MUTED;
    border: 1px solid $HAIRLINE;
    border-radius: 8px;
    padding: 10px;
    font-family: $FONT_MONO;
    font-size: 12px;
    selection-background-color: $ACCENT_STRONG;
    selection-color: #ffffff;
}

QScrollBar:vertical { background: transparent; width: 10px; margin: 4px 2px; }
QScrollBar::handle:vertical { background: $BORDER; border-radius: 3px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: $BORDER_STRONG; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px 4px; }
QScrollBar::handle:horizontal { background: $BORDER; border-radius: 3px; min-width: 28px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }

/* ---------- menus & popups ---------- */
QToolTip {
    background: $ELEVATED;
    color: $TEXT_STRONG;
    border: 1px solid $BORDER_STRONG;
    border-radius: 6px;
    padding: 5px 8px;
}
QMenu {
    background: $ELEVATED;
    color: $TEXT_STRONG;
    border: 1px solid $BORDER_STRONG;
    border-radius: 8px;
    padding: 4px;
}
QMenu::item { padding: 6px 20px 6px 12px; border-radius: 6px; }
QMenu::item:selected { background: $ACTIVE; color: $TEXT_STRONG; }
QMenu::item:disabled { color: $TEXT_FAINT; }
QMenu::separator { height: 1px; background: $BORDER; margin: 4px 6px; }
QMessageBox { background: $SURFACE; }
QMessageBox QLabel { color: $TEXT; }
""")


_QSS_TMPL = _build_qss()


def _draw_toggle(on: bool, scale: int, disabled: bool, active: tok.ThemeTokens) -> QImage:
    width, height = 32 * scale, 18 * scale
    image = QImage(width, height, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.transparent)
    p = QPainter(image)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setOpacity(0.45 if disabled else 1.0)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(active.accent_strong if on else active.border_strong))
    radius = height / 2
    p.drawRoundedRect(QRectF(0, 0, width, height), radius, radius)
    knob = height - 4 * scale
    x = width - knob - 2 * scale if on else 2 * scale
    p.setBrush(QColor("#FFFFFF" if on else active.surface))
    p.drawEllipse(QRectF(x, 2 * scale, knob, knob))
    p.end()
    return image


def _draw_chevron(scale: int, color: str) -> QImage:
    size = 12 * scale
    image = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.transparent)
    p = QPainter(image)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(color), 1.6 * scale)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.drawLine(QPointF(size * 0.22, size * 0.38), QPointF(size * 0.50, size * 0.66))
    p.drawLine(QPointF(size * 0.50, size * 0.66), QPointF(size * 0.78, size * 0.38))
    p.end()
    return image


def _toggle_images(active: tok.ThemeTokens) -> dict[str, str]:
    from app.paths import user_data_dir

    folder = user_data_dir() / "ui"
    folder.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    suffix = active.name
    for key, on, disabled in (
        ("TOGGLE_OFF", False, False),
        ("TOGGLE_ON", True, False),
        ("TOGGLE_OFF_DISABLED", False, True),
        ("TOGGLE_ON_DISABLED", True, True),
    ):
        base = folder / f"{key.lower()}_{suffix}.png"
        _draw_toggle(on, 1, disabled, active).save(str(base))
        _draw_toggle(on, 2, disabled, active).save(str(base.with_name(base.stem + "@2x.png")))
        paths[key] = Path(base).as_posix()

    chevron = folder / f"chevron_down_{suffix}.png"
    _draw_chevron(1, active.text_muted).save(str(chevron))
    _draw_chevron(2, active.text_muted).save(str(chevron.with_name(chevron.stem + "@2x.png")))
    paths["CHEVRON_DOWN"] = Path(chevron).as_posix()
    return paths


def stylesheet(active: tok.ThemeTokens | None = None) -> str:
    current = active or manager().tokens
    values = {
        "BG": current.bg,
        "SIDEBAR": current.sidebar,
        "SURFACE": current.surface,
        "ELEVATED": current.elevated,
        "CONTROL": current.control,
        "CONTROL_HOVER": current.control_hover,
        "ACTIVE": current.active,
        "INPUT": current.input,
        "HAIRLINE": current.hairline,
        "BORDER": current.border,
        "BORDER_STRONG": current.border_strong,
        "TEXT_STRONG": current.text_strong,
        "TEXT": current.text,
        "TEXT_MUTED": current.text_muted,
        "TEXT_FAINT": current.text_faint,
        "ACCENT": current.accent,
        "ACCENT_HOVER": current.accent_hover,
        "ACCENT_STRONG": current.accent_strong,
        "ACCENT_PRESSED": current.accent_pressed,
        "ACCENT_TEXT": current.accent_text,
        "ACCENT_SOFT_BG": current.accent_soft_bg,
        "ACCENT_SOFT_BORDER": current.accent_soft_border,
        "LINK": current.link,
        "OK": current.ok,
        "OK_SOFT_BG": current.ok_soft_bg,
        "OK_SOFT_BORDER": current.ok_soft_border,
        "WARN": current.warn,
        "WARN_SOFT_BG": current.warn_soft_bg,
        "WARN_SOFT_BORDER": current.warn_soft_border,
        "ERR": current.err,
        "ERR_SOFT_BG": current.err_soft_bg,
        "ERR_SOFT_BORDER": current.err_soft_border,
        "IDLE": current.idle,
        "FONT_UI": FONT_UI,
        "FONT_MONO": FONT_MONO,
    }
    values.update(_toggle_images(current))
    return _QSS_TMPL.substitute(values)


def _palette(active: tok.ThemeTokens) -> QPalette:
    pal = QPalette()
    roles = {
        QPalette.ColorRole.Window: active.bg,
        QPalette.ColorRole.WindowText: active.text,
        QPalette.ColorRole.Base: active.input,
        QPalette.ColorRole.AlternateBase: active.surface,
        QPalette.ColorRole.Text: active.text,
        QPalette.ColorRole.Button: active.control,
        QPalette.ColorRole.ButtonText: active.text_strong,
        QPalette.ColorRole.Highlight: active.accent_strong,
        QPalette.ColorRole.HighlightedText: active.accent_text,
        QPalette.ColorRole.ToolTipBase: active.elevated,
        QPalette.ColorRole.ToolTipText: active.text_strong,
        QPalette.ColorRole.PlaceholderText: active.text_faint,
        QPalette.ColorRole.Link: active.link,
        QPalette.ColorRole.Light: active.border_strong,
        QPalette.ColorRole.Mid: active.border,
        QPalette.ColorRole.Dark: active.bg,
    }
    for role, color in roles.items():
        pal.setColor(role, QColor(color))
    disabled = QPalette.ColorGroup.Disabled
    for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText):
        pal.setColor(disabled, role, QColor(active.text_faint))
    return pal


def serif_font(pixel_size: int) -> QFont:
    font = QFont()
    font.setFamilies(list(tok.SANS_FAMILIES))
    font.setPixelSize(pixel_size)
    font.setWeight(QFont.Weight.DemiBold)
    return font


def apply_window_titlebar(widget: QWidget, resolved: str | None = None) -> None:
    """Update Windows DWM dark/light titlebar and border to match active theme."""
    if sys.platform != "win32" or os.environ.get("QT_QPA_PLATFORM") == "offscreen":
        return
    try:
        import ctypes

        active = tok.LIGHT_TOKENS if (resolved or manager().resolved) == THEME_LIGHT else tok.DARK_TOKENS
        hwnd = int(widget.winId())
        dwm = ctypes.windll.dwmapi
        dark = ctypes.c_int(0 if active.name == THEME_LIGHT else 1)
        for attribute in (20, 19):
            if dwm.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(dark), ctypes.sizeof(dark)) == 0:
                break

        def colorref(hex_color: str) -> ctypes.c_uint:
            r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
            return ctypes.c_uint(b << 16 | g << 8 | r)

        caption = colorref(active.sidebar)
        border = colorref(active.hairline)
        dwm.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(caption), ctypes.sizeof(caption))
        dwm.DwmSetWindowAttribute(hwnd, 34, ctypes.byref(border), ctypes.sizeof(border))
    except (AttributeError, OSError, RuntimeError):
        pass


class ThemeManager(QObject):
    theme_changed = pyqtSignal(str, object)

    def __init__(self) -> None:
        super().__init__()
        self._mode = THEME_DARK
        self._resolved = THEME_DARK
        self._tokens = tok.DARK_TOKENS
        self._system_hooked = False

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def resolved(self) -> str:
        return self._resolved

    @property
    def tokens(self) -> tok.ThemeTokens:
        return self._tokens

    def _hook_system_changes(self, app: QApplication) -> None:
        if self._system_hooked:
            return
        self._system_hooked = True
        try:
            hints = app.styleHints()
            hints.colorSchemeChanged.connect(lambda *_: self._on_system_changed())
        except AttributeError:
            pass

    def _on_system_changed(self) -> None:
        if self._mode == THEME_SYSTEM:
            app = QApplication.instance()
            if isinstance(app, QApplication):
                self.apply(app, THEME_SYSTEM)

    def set_mode(self, mode: str, app: QApplication | None = None) -> str:
        normalized = mode if mode in THEME_MODES else THEME_DARK
        target_app = app or QApplication.instance()
        if isinstance(target_app, QApplication):
            self.apply(target_app, normalized)
        else:
            resolved, active = resolve_tokens(normalized)
            self._mode = normalized
            self._resolved = resolved
            self._tokens = active
            _sync_globals(active)
            self.theme_changed.emit(resolved, active)
        return self._mode

    def refresh_translations(self) -> None:
        _sync_globals(self._tokens)

    def apply(self, app: QApplication, mode: str | None = None) -> None:
        if mode is not None:
            self._mode = mode if mode in THEME_MODES else THEME_DARK
        self._hook_system_changes(app)
        resolved, active = resolve_tokens(self._mode)
        self._resolved = resolved
        self._tokens = active
        _sync_globals(active)

        cur_style = app.style()
        if cur_style is None or cur_style.objectName().lower() != "fusion":
            fusion = QStyleFactory.create("Fusion")
            if fusion is not None:
                app.setStyle(fusion)
        app.setPalette(_palette(active))
        font = QFont()
        font.setFamilies(list(tok.SANS_FAMILIES))
        font.setPixelSize(13)
        app.setFont(font)
        app.setStyleSheet(stylesheet(active))
        self.theme_changed.emit(resolved, active)


_MANAGER = ThemeManager()


def manager() -> ThemeManager:
    """Return global ThemeManager singleton."""
    return _MANAGER


def apply(app: QApplication, mode: str | None = None) -> None:
    """Apply active theme (or `mode`) to `QApplication`."""
    _MANAGER.apply(app, mode=mode)
