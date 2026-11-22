"""Тема в стиле Claude Desktop (@ant/cds), тёмный режим.

Токены — из SolasFor/Harness-UI, docs/claude-design-system.md:
* тёплый «обсидиан» вместо холодного серо-синего: холст #191919, сайдбар чуть
  СВЕТЛЕЕ холста (#1F1F1E), поднятые карточки #30302E со скруглением 16 px;
* один бренд-акцент Clay #D97757 — точечно: главная кнопка, фокус, индикаторы.
  Заголовки и жирный текст — молочно-белые, не рыжие;
* две роли шрифтов: антиква (Georgia) для заголовков страниц, гротеск (Segoe UI)
  для интерфейса, моноширинный для адресов, токенов и журнала;
* границы — тонкие 1 px линии без тяжёлых теней.

Цвета — в одном месте: окно, трей, иконки и эффекты берут их отсюда.
"""
from __future__ import annotations

from pathlib import Path
from string import Template

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QFont, QImage, QPainter, QPalette
from PyQt6.QtWidgets import QApplication, QStyleFactory

# ---------------------------------------------------------------------- поверхности
BG = "#191919"            # холст (--bg-300)
SIDEBAR = "#1F1F1E"       # сайдбар (--bg-200), чуть светлее холста
SURFACE = "#1F1F1E"       # карточки на холсте
ELEVATED = "#30302E"      # поднятая карточка, как композер Claude (--bg-000)
CONTROL = "#2C2C2A"       # кнопки (--cds-gray-750)
CONTROL_HOVER = "#353532"
ACTIVE = "#383835"        # выбранный пункт меню, сегмент (--cds-gray-700)
INPUT = "#141413"         # поля ввода и журнал — глубже холста
HAIRLINE = "#2A2A28"      # ≈ rgba(240,239,236,0.08) на холсте
BORDER = "#3A3A37"        # ≈ rgba(240,239,236,0.12)
BORDER_STRONG = "#4A4945"

# ---------------------------------------------------------------------- текст
TEXT_STRONG = "#F0EFEC"   # заголовки
TEXT = "#E8E7E2"          # основной
TEXT_MUTED = "#97958D"    # вторичный
TEXT_FAINT = "#737373"    # подписи, плейсхолдеры

# ---------------------------------------------------------------------- акцент
ACCENT = "#D97757"        # Clay
ACCENT_HOVER = "#E88B6D"
ACCENT_STRONG = "#C6613F" # заливка главной кнопки: белый текст читается (≈4:1)
ACCENT_PRESSED = "#B5562F"
ACCENT_TEXT = "#FFFFFF"
LINK = "#6DA7EC"

# ---------------------------------------------------------------------- статусы
OK = "#55BF50"
WARN = "#D9A440"
ERR = "#E66767"
IDLE = "#6B6A65"
ERR_SOFT_BG = "#2E1F1E"
ERR_SOFT_BORDER = "#563231"

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
    "server": ("server", LINK),
    "tunnel": ("tunnel", ACCENT),
    "app": ("app", "#A5A49A"),
}

SERIF_FAMILIES = ["Georgia", "Cambria", "Times New Roman"]
SANS_FAMILIES = ["Segoe UI Variable Text", "Segoe UI", "Inter"]
FONT_SERIF = '"Georgia", "Cambria", serif'
FONT_UI = '"Segoe UI Variable Text", "Segoe UI", "Inter", sans-serif'
FONT_MONO = '"Cascadia Mono", "JetBrains Mono", "Consolas", monospace'

_QSS = Template("""
* { outline: none; }
QWidget { color: $TEXT; font-family: $FONT_UI; font-size: 13px; }
QMainWindow, QWidget#Canvas { background: $BG; }
QScrollArea#Page, QScrollArea#Page > QWidget > QWidget { background: $BG; border: none; }

/* ---------- сайдбар ---------- */
QFrame#Sidebar { background: $SIDEBAR; border: none; border-right: 1px solid $HAIRLINE; }
QLabel#Wordmark { font-family: $FONT_SERIF; font-size: 19px; color: $TEXT_STRONG; }
QLabel#SidebarSection { color: $TEXT_FAINT; font-size: 11px; font-weight: 600; padding: 0 10px; }
QLabel#Version { color: $TEXT_FAINT; font-size: 11px; padding: 0 10px; }
QPushButton#Nav {
    background: transparent; border: none; border-radius: 8px;
    padding: 8px 10px; text-align: left; color: $TEXT_MUTED; font-weight: 500;
}
QPushButton#Nav:hover { background: $CONTROL; color: $TEXT; }
QPushButton#Nav:checked { background: $ACTIVE; color: $TEXT_STRONG; }
QFrame#StatusChip { background: $BG; border: 1px solid $HAIRLINE; border-radius: 10px; }
QLabel#ChipText { font-size: 12px; font-weight: 600; }
QLabel#ChipDetail { color: $TEXT_FAINT; font-size: 11px; }

/* ---------- типографика ---------- */
QLabel#PageTitle { font-family: $FONT_SERIF; font-size: 28px; color: $TEXT_STRONG; }
QLabel#PageLead { color: $TEXT_MUTED; font-size: 14px; }
QLabel#SectionTitle { color: $TEXT_STRONG; font-size: 14px; font-weight: 600; }
QLabel#FieldLabel { color: $TEXT_MUTED; font-size: 12px; font-weight: 600; }
QLabel#Hint { color: $TEXT_FAINT; font-size: 12px; }
QLabel#Error { color: $ERR; font-size: 12px; }
QLabel#Mono { font-family: $FONT_MONO; font-size: 13px; color: $TEXT_STRONG; }
QLabel#ServiceName { color: $TEXT; font-weight: 600; }
QLabel#ServiceDetail { color: $TEXT_FAINT; font-size: 12px; font-family: $FONT_MONO; }
QLabel#ServiceState { font-size: 12px; font-weight: 600; }
QLabel#Badge {
    background: $ERR_SOFT_BG; color: $ERR; border: 1px solid $ERR_SOFT_BORDER;
    border-radius: 8px; padding: 0 6px; font-size: 11px; font-weight: 600;
}

/* ---------- карточки ---------- */
QFrame#Card { background: $SURFACE; border: 1px solid $HAIRLINE; border-radius: 12px; }
QFrame#Elevated { background: $ELEVATED; border: 1px solid $BORDER; border-radius: 16px; }
QFrame#Divider { background: $HAIRLINE; border: none; max-height: 1px; min-height: 1px; }

/* ---------- кнопки ---------- */
QPushButton {
    background: $CONTROL; color: $TEXT; border: 1px solid $BORDER;
    border-radius: 8px; padding: 7px 14px; font-weight: 600;
}
QPushButton:hover { background: $CONTROL_HOVER; }
QPushButton:pressed { background: $HAIRLINE; }
QPushButton:disabled { color: $TEXT_FAINT; background: $SURFACE; border-color: $HAIRLINE; }

QPushButton#Primary {
    background: $ACCENT_STRONG; color: $ACCENT_TEXT; border: none;
    border-radius: 10px; padding: 11px 26px; font-size: 14px;
}
QPushButton#Primary:hover { background: $ACCENT; }
QPushButton#Primary:pressed { background: $ACCENT_PRESSED; }
QPushButton#Primary:disabled { background: $CONTROL; color: $TEXT_FAINT; }
QPushButton#Primary[running="true"] {
    background: transparent; color: $TEXT; border: 1px solid $BORDER_STRONG;
}
QPushButton#Primary[running="true"]:hover { background: $CONTROL; border-color: $ERR_SOFT_BORDER; color: $ERR; }
QPushButton#Primary[running="true"]:pressed { background: $ERR_SOFT_BG; }

QPushButton#Accent { background: $ACCENT_STRONG; color: $ACCENT_TEXT; border: none; }
QPushButton#Accent:hover { background: $ACCENT; }
QPushButton#Accent:pressed { background: $ACCENT_PRESSED; }
QPushButton#Accent:disabled { background: $CONTROL; color: $TEXT_FAINT; }

QPushButton#Ghost { background: transparent; border: none; color: $TEXT_MUTED; padding: 6px 8px; }
QPushButton#Ghost:hover { color: $TEXT; background: $CONTROL; }
QPushButton#Ghost:disabled { color: $TEXT_FAINT; background: transparent; }

QPushButton#Link { background: transparent; border: none; color: $LINK; padding: 2px 0; font-weight: 500; text-align: left; }
QPushButton#Link:hover { color: #8BBAF0; }

QFrame#SegmentGroup { background: $INPUT; border: 1px solid $HAIRLINE; border-radius: 10px; }
QPushButton#Segment {
    background: transparent; border: none; border-radius: 7px; padding: 6px 14px; color: $TEXT_MUTED;
}
QPushButton#Segment:hover { color: $TEXT; background: transparent; }
QPushButton#Segment:checked { background: $ACTIVE; color: $TEXT_STRONG; }

/* ---------- поля ---------- */
QLineEdit {
    background: $INPUT; color: $TEXT_STRONG; border: 1px solid $BORDER; border-radius: 8px;
    padding: 8px 10px; font-family: $FONT_MONO; font-size: 12px;
    selection-background-color: $ACCENT_STRONG; selection-color: #ffffff;
}
QLineEdit:hover { border-color: $BORDER_STRONG; }
QLineEdit:focus { border-color: $ACCENT; }
QLineEdit:read-only { color: $TEXT_MUTED; }
QLineEdit[invalid="true"] { border-color: $ERR; }

/* Переключатели вместо галочек — как в настройках Claude. Картинки рисует _toggle_images(). */
QCheckBox { spacing: 12px; padding: 5px 0; color: $TEXT; }
QCheckBox:disabled { color: $TEXT_FAINT; }
QCheckBox::indicator { width: 32px; height: 18px; image: url("$TOGGLE_OFF"); }
QCheckBox::indicator:checked { image: url("$TOGGLE_ON"); }
QCheckBox::indicator:disabled { image: url("$TOGGLE_OFF_DISABLED"); }
QCheckBox::indicator:checked:disabled { image: url("$TOGGLE_ON_DISABLED"); }

/* ---------- журнал ---------- */
QPlainTextEdit#Log {
    background: $INPUT; color: $TEXT_MUTED; border: 1px solid $HAIRLINE; border-radius: 12px;
    padding: 10px 8px; font-family: $FONT_MONO; font-size: 12px;
    selection-background-color: $ACCENT_STRONG; selection-color: #ffffff;
}

QScrollBar:vertical { background: transparent; width: 10px; margin: 4px 2px; }
QScrollBar::handle:vertical { background: $BORDER; border-radius: 3px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: $BORDER_STRONG; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px 4px; }
QScrollBar::handle:horizontal { background: $BORDER; border-radius: 3px; min-width: 28px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }

/* ---------- всплывающее ---------- */
QToolTip { background: $ELEVATED; color: $TEXT; border: 1px solid $BORDER; border-radius: 6px; padding: 5px 8px; }
QMenu { background: $ELEVATED; border: 1px solid $BORDER; border-radius: 10px; padding: 4px; }
QMenu::item { padding: 6px 22px 6px 14px; border-radius: 6px; }
QMenu::item:selected { background: $ACTIVE; }
QMenu::item:disabled { color: $TEXT_MUTED; }
QMenu::separator { height: 1px; background: $BORDER; margin: 4px 6px; }
QMessageBox { background: $SURFACE; }
QMessageBox QLabel { color: $TEXT; }
""")


# ---------------------------------------------------------------------- переключатели
def _draw_toggle(on: bool, scale: int, disabled: bool) -> QImage:
    width, height = 32 * scale, 18 * scale
    image = QImage(width, height, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.transparent)
    p = QPainter(image)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setOpacity(0.45 if disabled else 1.0)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(ACCENT_STRONG if on else BORDER))
    radius = height / 2
    p.drawRoundedRect(QRectF(0, 0, width, height), radius, radius)
    knob = height - 4 * scale
    x = width - knob - 2 * scale if on else 2 * scale
    p.setBrush(QColor("#FFFFFF" if on else TEXT_MUTED))
    p.drawEllipse(QRectF(x, 2 * scale, knob, knob))
    p.end()
    return image


def _toggle_images() -> dict[str, str]:
    """PNG для QCheckBox::indicator (1x и @2x — Qt сам берёт @2x на HiDPI)."""
    from app.paths import user_data_dir

    folder = user_data_dir() / "ui"
    folder.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    for key, on, disabled in (
        ("TOGGLE_OFF", False, False), ("TOGGLE_ON", True, False),
        ("TOGGLE_OFF_DISABLED", False, True), ("TOGGLE_ON_DISABLED", True, True),
    ):
        base = folder / f"{key.lower()}.png"
        _draw_toggle(on, 1, disabled).save(str(base))
        _draw_toggle(on, 2, disabled).save(str(base.with_name(base.stem + "@2x.png")))
        paths[key] = Path(base).as_posix()
    return paths


def stylesheet() -> str:
    values = {k: v for k, v in globals().items() if k.isupper() and isinstance(v, str)}
    values.update(_toggle_images())
    return _QSS.substitute(values)


def _palette() -> QPalette:
    pal = QPalette()
    roles = {
        QPalette.ColorRole.Window: BG,
        QPalette.ColorRole.WindowText: TEXT,
        QPalette.ColorRole.Base: INPUT,
        QPalette.ColorRole.AlternateBase: SURFACE,
        QPalette.ColorRole.Text: TEXT,
        QPalette.ColorRole.Button: CONTROL,
        QPalette.ColorRole.ButtonText: TEXT,
        QPalette.ColorRole.Highlight: ACCENT_STRONG,
        QPalette.ColorRole.HighlightedText: ACCENT_TEXT,
        QPalette.ColorRole.ToolTipBase: ELEVATED,
        QPalette.ColorRole.ToolTipText: TEXT,
        QPalette.ColorRole.PlaceholderText: TEXT_FAINT,
        QPalette.ColorRole.Link: LINK,
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


def serif_font(pixel_size: int) -> QFont:
    font = QFont()
    font.setFamilies(SERIF_FAMILIES)
    font.setPixelSize(pixel_size)
    return font


def apply(app: QApplication) -> None:
    """Fusion + тёмная палитра + QSS. Вызывать после QApplication, до создания окон."""
    fusion = QStyleFactory.create("Fusion")
    if fusion is not None:
        app.setStyle(fusion)
    app.setPalette(_palette())
    font = QFont()
    font.setFamilies(SANS_FAMILIES)
    font.setPixelSize(13)
    app.setFont(font)
    app.setStyleSheet(stylesheet())
