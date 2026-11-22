"""Тёмная тема: палитра Fusion + QSS, цвета и подписи статусов.

Принципы (impeccable, режим Operate — интерфейс служит задаче):
* один акцентный цвет только для главного действия и фокуса;
* нейтральные цвета слегка подкрашены в синий, а не чисто серые;
* цвета статусов значат одно и то же везде (окно, трей, журнал);
* никаких градиентов в тексте, «стекла» и цветных полос сбоку карточек;
* отступы кратны 4 px, иерархия — размером и насыщенностью шрифта.

Цвета — в одном месте: окно, трей, иконки и эффекты берут их отсюда.
"""
from __future__ import annotations

from string import Template

from PyQt6.QtGui import QColor, QFont, QPalette
from PyQt6.QtWidgets import QApplication, QStyleFactory

# ---------------------------------------------------------------------- поверхности
BG = "#0d0f13"            # фон окна и полей ввода
SURFACE = "#14171d"       # карточки
SURFACE_2 = "#1b1f27"     # кнопки, плашки
SURFACE_3 = "#242a34"     # наведение, выбранный сегмент
BORDER = "#232832"
BORDER_STRONG = "#323a47"

# ---------------------------------------------------------------------- текст
TEXT = "#e7eaf0"
TEXT_MUTED = "#9ba4b4"
TEXT_FAINT = "#687183"

# ---------------------------------------------------------------------- акцент
ACCENT = "#5b9cff"
ACCENT_LIGHT = "#84b5ff"
ACCENT_DARK = "#3f7fe6"
ACCENT_TEXT = "#08111f"   # текст на акцентной кнопке (контраст > 7:1)

# ---------------------------------------------------------------------- статусы
OK = "#3ccf8e"
WARN = "#e6b84a"
ERR = "#f26b6b"
IDLE = "#5c6474"
ERR_SOFT_BG = "#2a1a1e"
ERR_SOFT_BORDER = "#5a2c33"

# Общий статус (Overall.value) -> (подпись, цвет)
OVERALL = {
    "stopped": ("Остановлено", IDLE),
    "starting": ("Запуск…", WARN),
    "running": ("В сети", OK),
    "degraded": ("Переподключение…", WARN),
    "stopping": ("Остановка…", WARN),
    "error": ("Ошибка", ERR),
}
# Состояния «идёт процесс»: только у них анимация (пульс точки, блик на подписи).
PENDING = {"starting", "degraded", "stopping"}

# Состояние процесса (ProcState.value) -> (подпись, цвет)
SERVICE = {
    "stopped": ("Остановлен", IDLE),
    "starting": ("Подключается…", WARN),
    "running": ("Работает", OK),
    "stopping": ("Останавливается…", WARN),
    "failed": ("Ошибка", ERR),
}

# Источник строки журнала -> (метка, цвет метки)
LOG_SOURCES = {
    "server": ("server", "#7fb0ff"),
    "tunnel": ("tunnel", "#efa266"),
    "app": ("app", "#a6afbd"),
}

FONT_UI = '"Segoe UI Variable Text", "Segoe UI", "Inter", sans-serif'
FONT_MONO = '"Cascadia Mono", "Cascadia Code", "JetBrains Mono", "Consolas", monospace'

_QSS = Template("""
* { outline: none; }
QWidget { color: $TEXT; font-family: $FONT_UI; font-size: 13px; }
QMainWindow, QWidget#Root { background: $BG; }
QScrollArea#Scroll, QScrollArea#Scroll > QWidget > QWidget { background: $BG; border: none; }

/* ---------- типографика ---------- */
QLabel#AppTitle { font-size: 18px; font-weight: 600; }
QLabel#AppSubtitle { color: $TEXT_FAINT; font-size: 12px; }
QLabel#SectionTitle { font-size: 14px; font-weight: 600; }
QLabel#FieldLabel { color: $TEXT_MUTED; font-size: 12px; font-weight: 600; }
QLabel#Hint { color: $TEXT_FAINT; font-size: 12px; }
QLabel#Error { color: $ERR; font-size: 12px; }
QLabel#ServiceName { font-weight: 600; }
QLabel#ServiceDetail { color: $TEXT_FAINT; font-size: 12px; font-family: $FONT_MONO; }
QLabel#ServiceState { font-size: 12px; font-weight: 600; }
QLabel#Badge {
    background: $ERR_SOFT_BG; color: $ERR; border: 1px solid $ERR_SOFT_BORDER;
    border-radius: 9px; padding: 0 7px; font-size: 11px; font-weight: 600;
}

/* ---------- карточки ---------- */
QFrame#Card { background: $SURFACE; border: 1px solid $BORDER; border-radius: 12px; }
QFrame#Divider { background: $BORDER; border: none; max-height: 1px; min-height: 1px; }
QFrame#Pill { background: $SURFACE; border: 1px solid $BORDER; border-radius: 14px; }
QLabel#PillText { font-size: 12px; font-weight: 600; }

/* ---------- кнопки ---------- */
QPushButton {
    background: $SURFACE_2; color: $TEXT; border: 1px solid $BORDER_STRONG;
    border-radius: 8px; padding: 7px 14px; font-weight: 600;
}
QPushButton:hover { background: $SURFACE_3; }
QPushButton:pressed { background: $BORDER; }
QPushButton:disabled { color: $TEXT_FAINT; background: $SURFACE; border-color: $BORDER; }

QPushButton#Primary {
    background: $ACCENT; color: $ACCENT_TEXT; border: none;
    border-radius: 10px; padding: 11px 24px; font-size: 14px;
}
QPushButton#Primary:hover { background: $ACCENT_LIGHT; }
QPushButton#Primary:pressed { background: $ACCENT_DARK; }
QPushButton#Primary:disabled { background: $SURFACE_2; color: $TEXT_FAINT; }
QPushButton#Primary[running="true"] {
    background: $ERR_SOFT_BG; color: $ERR; border: 1px solid $ERR_SOFT_BORDER;
}
QPushButton#Primary[running="true"]:hover { background: #351f24; }
QPushButton#Primary[running="true"]:pressed { background: #2a1a1e; }

QPushButton#Accent { background: $ACCENT; color: $ACCENT_TEXT; border: none; }
QPushButton#Accent:hover { background: $ACCENT_LIGHT; }
QPushButton#Accent:pressed { background: $ACCENT_DARK; }

QPushButton#Ghost {
    background: transparent; border: none; color: $TEXT_MUTED; padding: 6px 8px;
}
QPushButton#Ghost:hover { color: $TEXT; background: $SURFACE_2; }
QPushButton#Ghost:disabled { color: $TEXT_FAINT; background: transparent; }

QPushButton#Disclosure {
    background: transparent; border: none; padding: 4px 2px; text-align: left;
    font-size: 14px; font-weight: 600; color: $TEXT;
}
QPushButton#Disclosure:hover { color: $ACCENT_LIGHT; background: transparent; }

QFrame#SegmentGroup { background: $BG; border: 1px solid $BORDER; border-radius: 9px; }
QPushButton#Segment {
    background: transparent; border: none; border-radius: 7px;
    padding: 6px 14px; color: $TEXT_MUTED;
}
QPushButton#Segment:hover { color: $TEXT; background: transparent; }
QPushButton#Segment:checked { background: $SURFACE_3; color: $TEXT; }

/* ---------- поля ---------- */
QLineEdit {
    background: $BG; color: $TEXT; border: 1px solid $BORDER_STRONG; border-radius: 8px;
    padding: 7px 10px; font-family: $FONT_MONO; font-size: 12px;
    selection-background-color: $ACCENT_DARK; selection-color: #ffffff;
}
QLineEdit:hover { border-color: #3d4655; }
QLineEdit:focus { border-color: $ACCENT; }
QLineEdit:read-only { color: $TEXT_MUTED; background: $SURFACE; }
QLineEdit[invalid="true"] { border-color: $ERR; }

QCheckBox { spacing: 10px; padding: 3px 0; }
QCheckBox:disabled { color: $TEXT_FAINT; }

/* ---------- журнал ---------- */
QPlainTextEdit#Log {
    background: $BG; color: $TEXT_MUTED; border: 1px solid $BORDER; border-radius: 10px;
    padding: 8px 6px; font-family: $FONT_MONO; font-size: 12px;
    selection-background-color: $ACCENT_DARK; selection-color: #ffffff;
}

QScrollBar:vertical { background: transparent; width: 10px; margin: 3px 2px; }
QScrollBar::handle:vertical { background: $BORDER_STRONG; border-radius: 3px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: $TEXT_FAINT; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px 3px; }
QScrollBar::handle:horizontal { background: $BORDER_STRONG; border-radius: 3px; min-width: 28px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }

/* ---------- всплывающее ---------- */
QToolTip {
    background: $SURFACE_3; color: $TEXT; border: 1px solid $BORDER_STRONG;
    border-radius: 6px; padding: 5px 8px;
}
QMenu { background: $SURFACE; border: 1px solid $BORDER_STRONG; border-radius: 8px; padding: 4px; }
QMenu::item { padding: 6px 20px 6px 14px; border-radius: 5px; }
QMenu::item:selected { background: $SURFACE_3; }
QMenu::item:disabled { color: $TEXT_MUTED; }
QMenu::separator { height: 1px; background: $BORDER; margin: 4px 6px; }
QMessageBox { background: $SURFACE; }
QMessageBox QLabel { color: $TEXT; }
""")


def stylesheet() -> str:
    return _QSS.substitute(globals())


def _palette() -> QPalette:
    pal = QPalette()
    roles = {
        QPalette.ColorRole.Window: BG,
        QPalette.ColorRole.WindowText: TEXT,
        QPalette.ColorRole.Base: BG,
        QPalette.ColorRole.AlternateBase: SURFACE,
        QPalette.ColorRole.Text: TEXT,
        QPalette.ColorRole.Button: SURFACE_2,
        QPalette.ColorRole.ButtonText: TEXT,
        QPalette.ColorRole.Highlight: ACCENT,
        QPalette.ColorRole.HighlightedText: ACCENT_TEXT,
        QPalette.ColorRole.ToolTipBase: SURFACE_3,
        QPalette.ColorRole.ToolTipText: TEXT,
        QPalette.ColorRole.PlaceholderText: TEXT_FAINT,
        QPalette.ColorRole.Link: ACCENT_LIGHT,
        QPalette.ColorRole.Light: BORDER_STRONG,
        QPalette.ColorRole.Mid: BORDER,
        QPalette.ColorRole.Dark: BG,
    }
    for role, color in roles.items():
        pal.setColor(role, QColor(color))
    disabled = QPalette.ColorGroup.Disabled
    for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText):
        pal.setColor(disabled, role, QColor(TEXT_FAINT))
    return pal


def apply(app: QApplication) -> None:
    """Fusion + тёмная палитра + QSS. Вызывать до создания окон."""
    fusion = QStyleFactory.create("Fusion")
    if fusion is not None:
        app.setStyle(fusion)
    app.setPalette(_palette())
    font = QFont()
    font.setFamilies(["Segoe UI Variable Text", "Segoe UI", "Inter"])
    font.setPixelSize(13)
    app.setFont(font)
    app.setStyleSheet(stylesheet())
