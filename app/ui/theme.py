"""ThemeManager (Dark / Light / System) and QSS styling in minimalist graphite desktop style."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from string import Template

from PyQt6.QtCore import QEvent, QObject, QPointF, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QGuiApplication, QImage, QPainter, QPalette, QPen
from PyQt6.QtWidgets import QApplication, QDialog, QMenu, QStyleFactory, QWidget

from app.ui import tokens as tok
from app.ui.i18n import tr

THEME_SYSTEM = "system"
THEME_DARK = "dark"
THEME_LIGHT = "light"
THEME_MODES = (THEME_SYSTEM, THEME_DARK, THEME_LIGHT)

# Dynamic active color tokens synced on every theme switch.
BG = tok.DARK_TOKENS.bg
SIDEBAR = tok.DARK_TOKENS.sidebar
SURFACE = tok.DARK_TOKENS.surface
ELEVATED = tok.DARK_TOKENS.elevated
CONTROL = tok.DARK_TOKENS.control
CONTROL_HOVER = tok.DARK_TOKENS.control_hover
CONTROL_PRESSED = tok.DARK_TOKENS.control_pressed
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
BTN_EMPHASIS = tok.DARK_TOKENS.btn_emphasis
BTN_EMPHASIS_HOVER = tok.DARK_TOKENS.btn_emphasis_hover
BTN_EMPHASIS_PRESSED = tok.DARK_TOKENS.btn_emphasis_pressed
BTN_EMPHASIS_BORDER = tok.DARK_TOKENS.btn_emphasis_border
BTN_EMPHASIS_TEXT = tok.DARK_TOKENS.btn_emphasis_text
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

SUCCESS = OK
WARNING = WARN
ERROR = ERR

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
    global BG, SIDEBAR, SURFACE, ELEVATED, CONTROL, CONTROL_HOVER, CONTROL_PRESSED, ACTIVE, INPUT
    global HAIRLINE, BORDER, BORDER_STRONG, TEXT_STRONG, TEXT, TEXT_MUTED, TEXT_FAINT
    global ACCENT, ACCENT_HOVER, ACCENT_STRONG, ACCENT_PRESSED, ACCENT_TEXT
    global ACCENT_SOFT_BG, ACCENT_SOFT_BORDER
    global BTN_EMPHASIS, BTN_EMPHASIS_HOVER, BTN_EMPHASIS_PRESSED, BTN_EMPHASIS_BORDER, BTN_EMPHASIS_TEXT
    global LINK, OK, OK_SOFT_BG, OK_SOFT_BORDER, WARN, WARN_SOFT_BG, WARN_SOFT_BORDER
    global ERR, ERR_SOFT_BG, ERR_SOFT_BORDER, IDLE, SUCCESS, WARNING, ERROR
    global OVERALL, SERVICE, LOG_SOURCES

    BG = active.bg
    SIDEBAR = active.sidebar
    SURFACE = active.surface
    ELEVATED = active.elevated
    CONTROL = active.control
    CONTROL_HOVER = active.control_hover
    CONTROL_PRESSED = active.control_pressed
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
    BTN_EMPHASIS = active.btn_emphasis
    BTN_EMPHASIS_HOVER = active.btn_emphasis_hover
    BTN_EMPHASIS_PRESSED = active.btn_emphasis_pressed
    BTN_EMPHASIS_BORDER = active.btn_emphasis_border
    BTN_EMPHASIS_TEXT = active.btn_emphasis_text
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
    SUCCESS = OK
    WARNING = WARN
    ERROR = ERR

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
        "server": ("backend", TEXT_STRONG),
        "backend": ("backend", TEXT_STRONG),
        "tunnel": ("tunnel", OK),
        "app": ("app", TEXT_MUTED),
        "oauth": ("oauth", TEXT_STRONG),
        "proxy": ("proxy", TEXT_MUTED),
        "computer_use": ("desktop", WARN),
        "gateway": ("gateway", TEXT_STRONG),
        "tasks": ("tasks", TEXT),
        "servers": ("servers", TEXT),
        "workspaces": ("work", TEXT),
        "extensions": ("ext", TEXT_STRONG),
        "ssh": ("ssh", WARN),
        "automation": ("auto", OK),
        "errors": ("errors", ERR),
        "crash": ("crash", ERR),
    }


_sync_globals(tok.DARK_TOKENS)


def animations_enabled() -> bool:
    """Return True only when OS reduced-motion is off and platform is interactive."""
    if QApplication.platformName() in ("offscreen", "minimal"):
        return False
    if sys.platform == "win32":
        try:
            import ctypes

            enabled = ctypes.c_int(1)
            # SPI_GETCLIENTAREAANIMATION = 0x1042
            if ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(enabled), 0):
                return bool(enabled.value)
        except (AttributeError, OSError):
            pass
    return True


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

/* ---------- sidebar & utility topbar ---------- */
QFrame#Sidebar {
    background: $SIDEBAR;
    border: none;
    border-right: 1px solid $HAIRLINE;
}
QFrame#TopBar {
    background: $BG;
    border: none;
}
QLabel#Wordmark {
    color: $TEXT_STRONG;
    font-size: 14px;
    font-weight: 600;
}
QPushButton#Nav {
    background: transparent;
    border: none;
    border-radius: 6px;
    padding: 5px 10px;
    min-height: 22px;
    text-align: left;
    color: $TEXT_MUTED;
    font-weight: 500;
    font-size: 13px;
}
QPushButton#Nav:hover {
    background: $CONTROL;
    color: $TEXT_STRONG;
}
QPushButton#Nav:pressed {
    background: $CONTROL_PRESSED;
}
QPushButton#Nav:focus {
    border: 1px solid $BORDER_STRONG;
}
QPushButton#Nav:checked {
    background: $ACTIVE;
    color: $TEXT_STRONG;
    font-weight: 500;
}
QPushButton#Nav[collapsed="true"] {
    padding: 5px 4px;
    text-align: center;
}
QFrame#SidebarFooter {
    background: transparent;
    border: none;
}
QLabel#SidebarStatus {
    color: $TEXT_MUTED;
    font-size: 12px;
    font-weight: 400;
}

/* ---------- typography ---------- */
QLabel#PageTitle {
    color: $TEXT_STRONG;
    font-size: 22px;
    font-weight: 700;
}
QLabel#PageLead { color: $TEXT_MUTED; font-size: 13px; }
QLabel#SectionTitle { color: $TEXT_STRONG; font-size: 14px; font-weight: 600; }
QLabel#HeroStatusTitle { color: $TEXT_STRONG; font-size: 15px; font-weight: 600; }
QLabel#FieldLabel { color: $TEXT; font-size: 12px; font-weight: 600; }
QLabel#SettingTitle { color: $TEXT; font-size: 13px; font-weight: 500; }
QLabel#Hint { color: $TEXT_MUTED; font-size: 12px; }
QLabel#Caption { color: $TEXT_FAINT; font-size: 11px; }
QLabel#Error { color: $ERR; font-size: 12px; font-weight: 500; }
QLabel#Mono { font-family: $FONT_MONO; font-size: 12px; color: $TEXT_STRONG; }
QLabel#ServiceName { color: $TEXT; font-weight: 500; font-size: 13px; }
QLabel#ServiceDetail { color: $TEXT_MUTED; font-size: 12px; font-family: $FONT_MONO; }
QLabel#ServiceState { color: $TEXT; font-size: 12px; font-weight: 500; }

/* ---------- badges & pills ---------- */
QLabel#Badge {
    background: $ERR_SOFT_BG;
    color: $ERR;
    border: 1px solid $ERR_SOFT_BORDER;
    border-radius: 5px;
    padding: 1px 6px;
    font-size: 11px;
    font-weight: 600;
}
QLabel#Pill {
    background: $CONTROL;
    color: $TEXT_MUTED;
    border: 1px solid $BORDER;
    border-radius: 5px;
    padding: 2px 7px;
    font-size: 11px;
    font-weight: 500;
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

/* ---------- surfaces, cards, copy field & banners ---------- */
QFrame#Card {
    background: $SURFACE;
    border: 1px solid $HAIRLINE;
    border-radius: 8px;
}
QFrame#Elevated {
    background: $ELEVATED;
    border: 1px solid $BORDER;
    border-radius: 8px;
}
QFrame#CopyField {
    background: $INPUT;
    border: 1px solid $BORDER;
    border-radius: 7px;
}
QLineEdit#CopyFieldInput {
    background: transparent;
    border: none;
    color: $TEXT_STRONG;
    font-family: $FONT_MONO;
    font-size: 13px;
    padding: 0 4px;
    selection-background-color: $ACCENT_STRONG;
    selection-color: $ACCENT_TEXT;
}
QPushButton#CopyFieldBtn {
    background: $CONTROL;
    color: $TEXT_STRONG;
    border: 1px solid $BORDER;
    border-radius: 5px;
    padding: 4px 12px;
    min-height: 20px;
    font-size: 12px;
    font-weight: 500;
}
QPushButton#CopyFieldBtn:hover {
    background: $CONTROL_HOVER;
    border-color: $BORDER_STRONG;
}
QPushButton#CopyFieldBtn:pressed {
    background: $CONTROL_PRESSED;
}
QPushButton#CopyFieldBtn:focus {
    border-color: $TEXT_MUTED;
}
QPushButton#CopyFieldBtn:disabled {
    color: $TEXT_FAINT;
    background: $SURFACE;
    border-color: $HAIRLINE;
}
QFrame#EmptyState {
    background: $SURFACE;
    border: 1px solid $HAIRLINE;
    border-radius: 8px;
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
    border-radius: 8px;
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
    border-radius: 6px;
    padding: 5px 12px;
    min-height: 20px;
    font-weight: 500;
    font-size: 12px;
}
QPushButton:hover {
    background: $CONTROL_HOVER;
    border-color: $BORDER_STRONG;
}
QPushButton:pressed { background: $CONTROL_PRESSED; }
QPushButton:focus { border-color: $TEXT_MUTED; }
QPushButton:disabled {
    color: $TEXT_FAINT;
    background: $SURFACE;
    border-color: $HAIRLINE;
}

/* Primary button: reserved exclusively for main server Start/Stop action */
QPushButton#Primary {
    background: $ACCENT_STRONG;
    color: $ACCENT_TEXT;
    border: 1px solid $ACCENT_STRONG;
    border-radius: 6px;
    padding: 6px 16px;
    min-height: 20px;
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
QPushButton#Primary:focus {
    border-color: $TEXT_STRONG;
}
QPushButton#Primary:disabled {
    background: $CONTROL;
    border-color: $HAIRLINE;
    color: $TEXT_FAINT;
}

/* Accent button: crisp neutral high-emphasis for Save/Add/Confirm actions */
QPushButton#Accent {
    background: $BTN_EMPHASIS;
    color: $BTN_EMPHASIS_TEXT;
    border: 1px solid $BTN_EMPHASIS_BORDER;
    border-radius: 6px;
    padding: 5px 13px;
    font-weight: 600;
}
QPushButton#Accent:hover {
    background: $BTN_EMPHASIS_HOVER;
    border-color: $BORDER_STRONG;
}
QPushButton#Accent:pressed {
    background: $BTN_EMPHASIS_PRESSED;
}
QPushButton#Accent:focus {
    border-color: $TEXT_MUTED;
}
QPushButton#Accent:disabled {
    background: $SURFACE;
    border-color: $HAIRLINE;
    color: $TEXT_FAINT;
}

QPushButton#Danger {
    background: $ERR_SOFT_BG;
    color: $ERR;
    border: 1px solid $ERR_SOFT_BORDER;
    border-radius: 6px;
    padding: 5px 12px;
    font-weight: 500;
}
QPushButton#Danger:hover {
    border-color: $ERR;
}
QPushButton#Danger:pressed {
    background: $CONTROL_PRESSED;
}
QPushButton#Danger:disabled {
    background: $SURFACE;
    border-color: $HAIRLINE;
    color: $TEXT_FAINT;
}

QPushButton#Ghost {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    color: $TEXT_MUTED;
    padding: 5px 9px;
}
QPushButton#Ghost:hover {
    color: $TEXT_STRONG;
    background: $CONTROL;
}
QPushButton#Ghost:pressed {
    background: $CONTROL_PRESSED;
}
QPushButton#Ghost:focus {
    border-color: $TEXT_MUTED;
}
QPushButton#Ghost:disabled {
    color: $TEXT_FAINT;
    background: transparent;
}

QPushButton#IconBtn {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 3px;
    min-height: 20px;
}
QPushButton#IconBtn:hover {
    background: $CONTROL;
    border-color: $HAIRLINE;
}
QPushButton#IconBtn:pressed {
    background: $CONTROL_PRESSED;
}
QPushButton#IconBtn:focus {
    border-color: $TEXT_MUTED;
}

QPushButton#Link {
    background: transparent;
    border: none;
    color: $LINK;
    padding: 2px 0;
    min-height: 18px;
    font-weight: 500;
    text-align: left;
}
QPushButton#Link:hover {
    text-decoration: underline;
}
QPushButton#Link:focus {
    color: $TEXT_STRONG;
    text-decoration: underline;
}

QPushButton#SubtleLink {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 5px;
    color: $TEXT_MUTED;
    padding: 4px 6px;
    min-height: 20px;
    font-size: 12px;
    font-weight: 400;
    text-align: left;
}
QPushButton#SubtleLink:hover {
    color: $TEXT_STRONG;
    background: $CONTROL;
}
QPushButton#SubtleLink:pressed {
    background: $CONTROL_PRESSED;
}
QPushButton#SubtleLink:focus {
    border-color: $TEXT_MUTED;
}

QFrame#SegmentGroup {
    background: $INPUT;
    border: 1px solid $BORDER;
    border-radius: 7px;
}
QPushButton#Segment {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 5px;
    padding: 4px 12px;
    min-height: 18px;
    color: $TEXT_MUTED;
    font-weight: 500;
}
QPushButton#Segment:hover { color: $TEXT_STRONG; }
QPushButton#Segment:checked {
    background: $ACTIVE;
    border-color: $BORDER;
    color: $TEXT_STRONG;
    font-weight: 500;
}

QPushButton#FilterPill {
    background: transparent;
    border: 1px solid $BORDER;
    border-radius: 6px;
    padding: 4px 12px;
    min-height: 20px;
    color: $TEXT_MUTED;
    font-size: 12px;
    font-weight: 500;
}
QPushButton#FilterPill:hover {
    background: $CONTROL;
    color: $TEXT_STRONG;
}
QPushButton#FilterPill:checked {
    background: $ACTIVE;
    border-color: $BORDER_STRONG;
    color: $TEXT_STRONG;
}

/* ---------- inputs, spinboxes & combos ---------- */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox {
    background: $INPUT;
    color: $TEXT_STRONG;
    border: 1px solid $BORDER;
    border-radius: 6px;
    padding: 5px 10px;
    min-height: 20px;
    font-size: 12px;
    selection-background-color: $ACCENT_STRONG;
    selection-color: $ACCENT_TEXT;
}
QLineEdit { font-family: $FONT_MONO; }
QLineEdit#UiInput { font-family: $FONT_UI; font-size: 13px; }
QLineEdit:hover, QTextEdit:hover, QPlainTextEdit:hover, QSpinBox:hover, QDoubleSpinBox:hover {
    border-color: $BORDER_STRONG;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {
    border-color: $TEXT_MUTED;
}
QLineEdit:read-only, QTextEdit[readOnly="true"], QPlainTextEdit[readOnly="true"] { color: $TEXT_MUTED; }
QLineEdit:read-only:hover, QTextEdit[readOnly="true"]:hover, QPlainTextEdit[readOnly="true"]:hover {
    border-color: $BORDER;
}
QTextEdit[readOnly="true"]:focus, QPlainTextEdit[readOnly="true"]:focus {
    border-color: $BORDER;
}
QPlainTextEdit#Log:hover, QTextEdit#Log:hover {
    border-color: $HAIRLINE;
}
QPlainTextEdit#ConsoleLog {
    font-family: $FONT_MONO;
    font-size: 12px;
    color: $TEXT;
}
QLineEdit[invalid="true"] { border-color: $ERR; }
QSpinBox::up-button, QSpinBox::down-button, QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {
    width: 18px;
    border: none;
    background: transparent;
}

QComboBox {
    background: $INPUT;
    color: $TEXT_STRONG;
    border: 1px solid $BORDER;
    border-radius: 6px;
    padding: 5px 26px 5px 10px;
    min-height: 20px;
    font-size: 12px;
    font-weight: 500;
}
QComboBox:hover { border-color: $BORDER_STRONG; }
QComboBox:focus, QComboBox:on { border-color: $TEXT_MUTED; }
QComboBox:disabled { color: $TEXT_FAINT; background: $SURFACE; border-color: $HAIRLINE; }
QComboBox::drop-down {
    subcontrol-origin: border;
    subcontrol-position: center right;
    width: 24px;
    border: none;
    background: transparent;
}
QComboBox#TableCombo {
    min-height: 0px;
    padding: 3px 26px 3px 9px;
    border-radius: 5px;
    font-size: 12px;
}
QComboBox#TableCombo::drop-down {
    width: 22px;
}
QPushButton#RowMenuBtn {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 5px;
    padding: 2px 4px;
    min-height: 0px;
    min-width: 24px;
}
QPushButton#RowMenuBtn:hover {
    background: $CONTROL;
    border-color: $BORDER;
}
QPushButton#RowMenuBtn:pressed {
    background: $CONTROL_PRESSED;
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
    border-radius: 6px;
    padding: 4px;
    selection-background-color: $ACTIVE;
    selection-color: $TEXT_STRONG;
}

QComboBox#ThemeCombo {
    background: transparent;
    border: 1px solid $HAIRLINE;
    border-radius: 6px;
    padding: 3px 24px 3px 8px;
    min-height: 18px;
    font-size: 12px;
    font-weight: 500;
    color: $TEXT_MUTED;
}
QComboBox#ThemeCombo:hover {
    background: $CONTROL;
    border-color: $BORDER;
    color: $TEXT_STRONG;
}
QComboBox#ThemeCombo:focus {
    border-color: $TEXT_MUTED;
}
QComboBox#ThemeCombo::drop-down { width: 20px; }

/* ---------- tabs & splitters ---------- */
QTabWidget::pane {
    border: none;
    border-top: 1px solid $HAIRLINE;
    background: transparent;
    padding-top: 12px;
}
QTabBar::tab {
    background: transparent;
    color: $TEXT_MUTED;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 6px 12px;
    margin-right: 4px;
    font-size: 13px;
    font-weight: 500;
}
QTabBar::tab:hover {
    color: $TEXT_STRONG;
}
QTabBar::tab:selected {
    color: $TEXT_STRONG;
    font-weight: 600;
    border-bottom: 2px solid $ACCENT;
}
QTabBar::tab:focus {
    color: $TEXT_STRONG;
}
QSplitter::handle {
    background: $HAIRLINE;
}
QSplitter::handle:hover {
    background: $BORDER_STRONG;
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
QTableWidget:focus {
    border-color: $BORDER_STRONG;
}
QTableWidget::item {
    padding: 5px 10px;
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
    padding: 6px 10px;
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
    border-radius: 6px;
    padding: 7px 10px;
    margin: 1px 0;
}
QListWidget::item:hover { background: $CONTROL; }
QListWidget::item:selected {
    background: $ACTIVE;
    color: $TEXT_STRONG;
}

/* ---------- toggles & checkboxes ---------- */
QCheckBox { spacing: 8px; padding: 3px 0; color: $TEXT; font-size: 13px; }
QCheckBox:disabled { color: $TEXT_FAINT; }
QCheckBox::indicator { width: 32px; height: 18px; image: url("$TOGGLE_OFF"); }
QCheckBox::indicator:checked { image: url("$TOGGLE_ON"); }
QCheckBox::indicator:disabled { image: url("$TOGGLE_OFF_DISABLED"); }
QCheckBox::indicator:checked:disabled { image: url("$TOGGLE_ON_DISABLED"); }

/* ---------- log viewer ---------- */
QPlainTextEdit#Log {
    background: $INPUT;
    color: $TEXT;
    border: 1px solid $HAIRLINE;
    border-radius: 8px;
    padding: 10px;
    font-family: $FONT_MONO;
    font-size: 12px;
    selection-background-color: $ACCENT_STRONG;
    selection-color: $ACCENT_TEXT;
}

QScrollBar:vertical { background: transparent; width: 9px; margin: 3px 2px; }
QScrollBar::handle:vertical { background: $BORDER; border-radius: 3px; min-height: 24px; }
QScrollBar::handle:vertical:hover { background: $BORDER_STRONG; }
QScrollBar:horizontal { background: transparent; height: 9px; margin: 2px 3px; }
QScrollBar::handle:horizontal { background: $BORDER; border-radius: 3px; min-width: 24px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }

/* ---------- menus & popups ---------- */
QToolTip {
    background: $ELEVATED;
    color: $TEXT_STRONG;
    border: 1px solid $BORDER_STRONG;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 12px;
}
QMenu {
    background: $ELEVATED;
    color: $TEXT_STRONG;
    border: 1px solid $BORDER_STRONG;
    border-radius: 8px;
    padding: 4px;
}
QMenu::item { padding: 6px 18px 6px 12px; border-radius: 5px; font-size: 12px; }
QMenu::item:selected { background: $ACTIVE; color: $TEXT_STRONG; }
QMenu::item:disabled { color: $TEXT_FAINT; }
QMenu::separator { height: 1px; background: $HAIRLINE; margin: 4px 6px; }
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
    pen = QPen(QColor(color), 1.5 * scale)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.drawLine(QPointF(size * 0.24, size * 0.38), QPointF(size * 0.50, size * 0.64))
    p.drawLine(QPointF(size * 0.50, size * 0.64), QPointF(size * 0.76, size * 0.38))
    p.end()
    return image


_TOGGLE_CACHE: dict[tuple[str, str], dict[str, str]] = {}
_QSS_CACHE: dict[tuple[str, str], str] = {}
_PALETTE_CACHE: dict[str, QPalette] = {}


def _toggle_images(active: tok.ThemeTokens) -> dict[str, str]:
    from app.paths import user_data_dir

    folder = user_data_dir() / "ui"
    suffix = active.name
    cache_key = (str(folder), f"v2_{suffix}")
    cached = _TOGGLE_CACHE.get(cache_key)
    if cached is not None and all(Path(p).exists() for p in cached.values()):
        return cached

    folder.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    for key, on, disabled in (
        ("TOGGLE_OFF", False, False),
        ("TOGGLE_ON", True, False),
        ("TOGGLE_OFF_DISABLED", False, True),
        ("TOGGLE_ON_DISABLED", True, True),
    ):
        base = folder / f"v2_{key.lower()}_{suffix}.png"
        base_2x = base.with_name(base.stem + "@2x.png")
        if not base.exists():
            _draw_toggle(on, 1, disabled, active).save(str(base))
        if not base_2x.exists():
            _draw_toggle(on, 2, disabled, active).save(str(base_2x))
        paths[key] = Path(base).as_posix()

    chevron = folder / f"v2_chevron_down_{suffix}.png"
    chevron_2x = chevron.with_name(chevron.stem + "@2x.png")
    if not chevron.exists():
        _draw_chevron(1, active.text_muted).save(str(chevron))
    if not chevron_2x.exists():
        _draw_chevron(2, active.text_muted).save(str(chevron_2x))
    paths["CHEVRON_DOWN"] = Path(chevron).as_posix()
    _TOGGLE_CACHE[cache_key] = paths
    return paths


def stylesheet(active: tok.ThemeTokens | None = None) -> str:
    current = active or manager().tokens
    toggle_paths = _toggle_images(current)
    cache_key = (toggle_paths["TOGGLE_OFF"], current.name)
    cached_qss = _QSS_CACHE.get(cache_key)
    if cached_qss is not None:
        return cached_qss
    values = {
        "BG": current.bg,
        "SIDEBAR": current.sidebar,
        "SURFACE": current.surface,
        "ELEVATED": current.elevated,
        "CONTROL": current.control,
        "CONTROL_HOVER": current.control_hover,
        "CONTROL_PRESSED": current.control_pressed,
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
        "BTN_EMPHASIS": current.btn_emphasis,
        "BTN_EMPHASIS_HOVER": current.btn_emphasis_hover,
        "BTN_EMPHASIS_PRESSED": current.btn_emphasis_pressed,
        "BTN_EMPHASIS_BORDER": current.btn_emphasis_border,
        "BTN_EMPHASIS_TEXT": current.btn_emphasis_text,
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
    values.update(toggle_paths)
    rendered = _QSS_TMPL.substitute(values)
    _QSS_CACHE[cache_key] = rendered
    return rendered


def _palette(active: tok.ThemeTokens) -> QPalette:
    cached = _PALETTE_CACHE.get(active.name)
    if cached is not None:
        return cached
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
    _PALETTE_CACHE[active.name] = pal
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


class _PopupThemeFilter(QObject):
    """Applies the cached QSS lazily to newly opened dialogs and context menus."""

    def __init__(self, theme_mgr: ThemeManager, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._mgr = theme_mgr

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:  # noqa: N802
        if (
            event is not None
            and event.type() == QEvent.Type.Show
            and isinstance(obj, QWidget)
            and obj.isWindow()
            and isinstance(obj, (QDialog, QMenu))
            and obj.objectName() != "MainWindow"
        ):
            self._mgr.apply_to_widget(obj)
            if isinstance(obj, QDialog):
                apply_window_titlebar(obj)
        return False


class ThemeManager(QObject):
    theme_changed = pyqtSignal(str, object)

    def __init__(self) -> None:
        super().__init__()
        self._mode = THEME_DARK
        self._resolved = THEME_DARK
        self._tokens = tok.DARK_TOKENS
        self._version = 1
        self._system_hooked = False
        self._style_initialized = False
        self._font_initialized = False
        self._applied_mode: str | None = None
        self._applied_resolved: str | None = None
        self._popup_filter: _PopupThemeFilter | None = None

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def resolved(self) -> str:
        return self._resolved

    @property
    def tokens(self) -> tok.ThemeTokens:
        return self._tokens

    @property
    def version(self) -> int:
        return self._version

    @property
    def current_stylesheet(self) -> str:
        return stylesheet(self._tokens)

    def apply_to_widget(self, widget: QWidget, active: tok.ThemeTokens | None = None) -> bool:
        """Apply active QSS to a widget subtree only when theme version changed."""
        target_version = self._version if active is None else None
        if target_version is not None and widget.property("_mcp_theme_version") == target_version:
            return False
        widget.setStyleSheet(stylesheet(active or self._tokens))
        if target_version is not None:
            widget.setProperty("_mcp_theme_version", target_version)
        return True

    def _hook_system_changes(self, app: QApplication) -> None:
        if self._popup_filter is None:
            self._popup_filter = _PopupThemeFilter(self, app)
            app.installEventFilter(self._popup_filter)
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
            if self._applied_mode == normalized and self._applied_resolved == resolved:
                return self._mode
            self._mode = normalized
            self._resolved = resolved
            self._tokens = active
            self._applied_mode = normalized
            self._applied_resolved = resolved
            self._version += 1
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
        if (
            self._style_initialized
            and self._applied_mode == self._mode
            and self._applied_resolved == resolved
        ):
            return
        self._resolved = resolved
        self._tokens = active
        self._applied_mode = self._mode
        self._applied_resolved = resolved
        self._version += 1
        _sync_globals(active)

        if not self._style_initialized:
            cur_style = app.style()
            if cur_style is None or cur_style.objectName().lower() != "fusion":
                fusion = QStyleFactory.create("Fusion")
                if fusion is not None:
                    app.setStyle(fusion)
            self._style_initialized = True
        if not self._font_initialized:
            font = QFont()
            font.setFamilies(list(tok.SANS_FAMILIES))
            font.setPixelSize(13)
            app.setFont(font)
            self._font_initialized = True

        app.setPalette(_palette(active))
        if app.styleSheet():
            app.setStyleSheet("")
        for top in app.topLevelWidgets():
            if top.isVisible() and isinstance(top, (QDialog, QMenu)) and top.objectName() != "MainWindow":
                self.apply_to_widget(top, active)
                if isinstance(top, QDialog):
                    apply_window_titlebar(top)
        self.theme_changed.emit(resolved, active)


_MANAGER = ThemeManager()


def manager() -> ThemeManager:
    """Return global ThemeManager singleton."""
    return _MANAGER


def apply(app: QApplication, mode: str | None = None) -> None:
    """Apply active theme (or `mode`) to `QApplication`."""
    _MANAGER.apply(app, mode=mode)


def apply_to_widget(widget: QWidget, active: tok.ThemeTokens | None = None) -> bool:
    """Apply active QSS to a widget subtree only when theme version changed."""
    return _MANAGER.apply_to_widget(widget, active=active)
