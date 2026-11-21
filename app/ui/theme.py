"""Тёмная тема: палитра Fusion + QSS, цвета и подписи статусов.

Цвета — в одном месте: окно, трей и иконки берут их отсюда.
"""
from __future__ import annotations

from string import Template

from PyQt6.QtGui import QColor, QFont, QPalette
from PyQt6.QtWidgets import QApplication

# ---------------------------------------------------------------- палитра
BG = "#0f1117"
SURFACE = "#171a23"
SURFACE_2 = "#1f2330"
INPUT = "#0b0d12"
BORDER = "#2a2f3f"
TEXT = "#e6e8ef"
TEXT_DIM = "#8b91a5"

ACCENT = "#6366f1"
ACCENT_HOVER = "#7679f6"
ACCENT_PRESSED = "#5458e8"
ACCENT_LIGHT = "#818cf8"   # градиент иконки
ACCENT_DARK = "#4f46e5"

GREEN = "#22c55e"
RED = "#ef4444"
RED_TEXT = "#fca5a5"
AMBER = "#f59e0b"
GRAY = "#6b7280"
BLUE = "#38bdf8"     # источник [server] в логах
VIOLET = "#a78bfa"   # источник [tunnel] в логах


def rgba(hex_color: str, alpha: float) -> str:
    """'#rrggbb' + прозрачность 0..1 -> 'rgba(r, g, b, a)' для QSS (a в 0..255)."""
    c = QColor(hex_color)
    return f"rgba({c.red()}, {c.green()}, {c.blue()}, {round(alpha * 255)})"


# ---------------------------------------------------------------- статусы
# Ключи — значения enum'ов Overall и ProcState из app.core (это str-enum'ы).
OVERALL = {
    "stopped": ("Остановлено", GRAY),
    "starting": ("Запуск…", AMBER),
    "running": ("Работает", GREEN),
    "degraded": ("Восстановление…", AMBER),
    "stopping": ("Остановка…", AMBER),
    "error": ("Ошибка", RED),
}
SERVER_STATES = {
    "stopped": ("Остановлен", GRAY),
    "starting": ("Запускается…", AMBER),
    "running": ("Запущен", GREEN),
    "stopping": ("Останавливается…", AMBER),
    "failed": ("Ошибка", RED),
}
TUNNEL_STATES = {
    "stopped": ("Отключён", GRAY),
    "starting": ("Подключается…", AMBER),
    "running": ("Активен", GREEN),
    "stopping": ("Отключается…", AMBER),
    "failed": ("Ошибка", RED),
}


# ---------------------------------------------------------------- QSS
# string.Template ($NAME), а не f-строка: в QSS много фигурных скобок.
_QSS = Template("""
QMainWindow, QWidget#Root { background: $BG; }
QLabel { background: transparent; }
QLabel#Title { font-size: 15pt; font-weight: 600; }
QLabel#Dim { color: $TEXT_DIM; }
QLabel#Section { color: $TEXT_DIM; font-size: 8pt; font-weight: 700; }
QLabel#RowTitle { font-weight: 600; }

QFrame#Card { background: $SURFACE; border: 1px solid $BORDER; border-radius: 12px; }
QFrame#Divider { background: $BORDER; border: none; }

QPushButton {
    background: $SURFACE_2; color: $TEXT;
    border: 1px solid $BORDER; border-radius: 8px; padding: 7px 14px;
}
QPushButton:hover { border-color: $ACCENT; }
QPushButton:pressed { background: $BORDER; }
QPushButton:disabled { color: $TEXT_DIM; border-color: $BORDER; }
QPushButton#Small { padding: 4px 10px; font-size: 9pt; }

QPushButton#Primary {
    background: $ACCENT; color: #ffffff; border: none; border-radius: 10px;
    font-size: 11pt; font-weight: 600; padding: 12px 18px;
}
QPushButton#Primary:hover { background: $ACCENT_HOVER; }
QPushButton#Primary:pressed { background: $ACCENT_PRESSED; }
QPushButton#Primary:disabled { background: $BORDER; color: $TEXT_DIM; }
QPushButton#Primary[running="true"] { background: $RED_SOFT; color: $RED_TEXT; border: 1px solid $RED_BORDER; }
QPushButton#Primary[running="true"]:hover { background: $RED_SOFT_HOVER; }

QLineEdit {
    background: $INPUT; color: $TEXT; border: 1px solid $BORDER; border-radius: 8px;
    padding: 7px 10px; selection-background-color: $ACCENT;
}
QLineEdit:focus { border-color: $ACCENT; }

QPlainTextEdit#Log {
    background: $INPUT; color: $TEXT; border: 1px solid $BORDER; border-radius: 10px;
    padding: 6px; selection-background-color: $ACCENT;
}

QToolButton#Disclosure { background: transparent; border: none; color: $TEXT; font-weight: 600; padding: 2px 0; }
QToolButton#Disclosure:hover { color: $ACCENT_HOVER; }

QCheckBox { background: transparent; spacing: 8px; }

QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: $BORDER; border-radius: 3px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: $TEXT_DIM; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: $BORDER; border-radius: 3px; min-width: 28px; }
QScrollBar::handle:horizontal:hover { background: $TEXT_DIM; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }

QMenu { background: $SURFACE; color: $TEXT; border: 1px solid $BORDER; padding: 4px; }
QMenu::item { padding: 6px 22px 6px 14px; border-radius: 4px; }
QMenu::item:selected { background: $ACCENT; color: #ffffff; }
QMenu::item:disabled { color: $TEXT_DIM; }
QMenu::separator { height: 1px; background: $BORDER; margin: 4px 6px; }

QToolTip { background: $SURFACE_2; color: $TEXT; border: 1px solid $BORDER; padding: 4px; }
""")

STYLESHEET = _QSS.substitute(
    BG=BG, SURFACE=SURFACE, SURFACE_2=SURFACE_2, INPUT=INPUT, BORDER=BORDER,
    TEXT=TEXT, TEXT_DIM=TEXT_DIM,
    ACCENT=ACCENT, ACCENT_HOVER=ACCENT_HOVER, ACCENT_PRESSED=ACCENT_PRESSED,
    RED_TEXT=RED_TEXT, RED_SOFT=rgba(RED, 0.12), RED_SOFT_HOVER=rgba(RED, 0.2),
    RED_BORDER=rgba(RED, 0.55),
)


def apply(app: QApplication) -> None:
    """Fusion + тёмная палитра (диалоги, чекбоксы, меню) + QSS (карточки, кнопки)."""
    app.setStyle("Fusion")

    font = QFont("Segoe UI")
    font.setPointSizeF(10)
    app.setFont(font)  # шрифт задаём кодом, не в QSS: QSS перебил бы моноширинный шрифт логов

    role = QPalette.ColorRole
    pal = QPalette()
    pal.setColor(role.Window, QColor(BG))
    pal.setColor(role.WindowText, QColor(TEXT))
    pal.setColor(role.Base, QColor(INPUT))
    pal.setColor(role.AlternateBase, QColor(SURFACE))
    pal.setColor(role.Text, QColor(TEXT))
    pal.setColor(role.PlaceholderText, QColor(TEXT_DIM))
    pal.setColor(role.Button, QColor(SURFACE_2))
    pal.setColor(role.ButtonText, QColor(TEXT))
    pal.setColor(role.Highlight, QColor(ACCENT))
    pal.setColor(role.HighlightedText, QColor("#ffffff"))
    pal.setColor(role.ToolTipBase, QColor(SURFACE_2))
    pal.setColor(role.ToolTipText, QColor(TEXT))
    pal.setColor(role.Link, QColor(ACCENT_LIGHT))
    disabled = QPalette.ColorGroup.Disabled
    for r in (role.WindowText, role.Text, role.ButtonText):
        pal.setColor(disabled, r, QColor(TEXT_DIM))
    app.setPalette(pal)

    app.setStyleSheet(STYLESHEET)
