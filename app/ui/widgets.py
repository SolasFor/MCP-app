"""Небольшие виджеты главного окна: карточка, индикатор статуса, панель логов."""
from __future__ import annotations

import re
from collections import deque
from datetime import datetime
from html import escape

from PyQt6.QtCore import QRectF, Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QPainter, QPaintEvent
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPlainTextEdit, QVBoxLayout, QWidget

from app.ui import theme

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_ERR = re.compile(r"✖|\b(ERR|ERROR|CRITICAL|FATAL|Traceback)\b")
_WARN = re.compile(r"⚠|\b(WRN|WARN|WARNING)\b")


# ====================================================================== layout helpers
def card() -> tuple[QFrame, QVBoxLayout]:
    """Скруглённая карточка (QFrame#Card) и её вертикальный layout."""
    frame = QFrame()
    frame.setObjectName("Card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(10)
    return frame, layout


def divider() -> QFrame:
    line = QFrame()
    line.setObjectName("Divider")
    line.setFixedHeight(1)
    return line


def section_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("Section")
    return label


# ====================================================================== статус
class StatusDot(QWidget):
    """Цветная точка с ореолом; в промежуточных состояниях мигает."""

    def __init__(self, diameter: int = 12, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._diameter = diameter
        self._color = QColor(theme.GRAY)
        self._pulse = False
        self._bright = True
        self.setFixedSize(diameter + 10, diameter + 10)
        self._timer = QTimer(self)
        self._timer.setInterval(550)
        self._timer.timeout.connect(self._tick)

    def set_state(self, color: str, pulse: bool) -> None:
        self._color = QColor(color)
        self._pulse = pulse
        if pulse and not self._timer.isActive():
            self._timer.start()
        elif not pulse:
            self._timer.stop()
            self._bright = True
        self.update()

    def _tick(self) -> None:
        self._bright = not self._bright
        self.update()

    def paintEvent(self, _event: QPaintEvent) -> None:
        color = QColor(self._color)
        if self._pulse and not self._bright:
            color.setAlphaF(0.35)
        halo = QColor(color)
        halo.setAlphaF(color.alphaF() * 0.22)

        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(halo)
        p.drawEllipse(QRectF(self.rect()))
        margin = (self.width() - self._diameter) / 2
        p.setBrush(color)
        p.drawEllipse(QRectF(margin, margin, self._diameter, self._diameter))
        p.end()


class StatusRow(QWidget):
    """●  Заголовок / подпись мелким шрифтом  ……  Состояние"""

    def __init__(self, title: str, detail: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(10)

        self.dot = StatusDot()
        texts = QVBoxLayout()
        texts.setSpacing(1)
        self.title = QLabel(title)
        self.title.setObjectName("RowTitle")
        self.detail = QLabel(detail)
        self.detail.setObjectName("Dim")
        texts.addWidget(self.title)
        texts.addWidget(self.detail)

        self.state = QLabel()
        self.state.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        layout.addWidget(self.dot, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(texts, 1)
        layout.addWidget(self.state, 0, Qt.AlignmentFlag.AlignVCenter)

    def set_state(self, text: str, color: str, pulse: bool = False) -> None:
        self.dot.set_state(color, pulse)
        self.state.setText(text)
        self.state.setStyleSheet(f"color: {color}; font-weight: 600;")


# ====================================================================== логи
class LogView(QPlainTextEdit):
    """Только для чтения, цветные источники, лимит строк, пакетная отрисовка.

    Строки копятся в очереди и выводятся раз в 80 мс одним проходом — даже
    если сервер выдаёт тысячи строк в секунду, окно не подвисает.
    Автопрокрутка работает, только если пользователь сам не прокрутил лог вверх.
    """

    SOURCE_COLORS = {"server": theme.BLUE, "tunnel": theme.VIOLET, "app": theme.TEXT_DIM}
    LEVEL_COLORS = {"error": theme.RED, "warn": theme.AMBER, "ok": theme.GREEN}
    MAX_PENDING = 2000

    def __init__(self, max_lines: int = 5000, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Log")
        self.setReadOnly(True)
        self.setUndoRedoEnabled(False)
        self.setMaximumBlockCount(max_lines)  # старые строки удаляются сами
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        font = QFont()
        font.setFamilies(["Cascadia Mono", "Consolas", "Courier New"])
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSizeF(9)
        self.setFont(font)

        self._pending: deque[str] = deque(maxlen=self.MAX_PENDING)
        self._dropped = 0
        self._flush_timer = QTimer(self)
        self._flush_timer.setSingleShot(True)
        self._flush_timer.setInterval(80)
        self._flush_timer.timeout.connect(self.flush_pending)

    @staticmethod
    def level(line: str) -> str:
        if _ERR.search(line):
            return "error"
        if _WARN.search(line):
            return "warn"
        if "✔" in line:
            return "ok"
        return ""

    def append_line(self, source: str, line: str) -> None:
        line = _ANSI.sub("", line)
        stamp = datetime.now().strftime("%H:%M:%S")
        color = self.LEVEL_COLORS.get(self.level(line), theme.TEXT)
        source_color = self.SOURCE_COLORS.get(source, theme.TEXT_DIM)
        html = (
            '<span style="white-space:pre">'
            f'<span style="color:{theme.TEXT_DIM}">{stamp}</span>  '
            f'<span style="color:{source_color}">{escape(source.ljust(6))}</span>  '
            f'<span style="color:{color}">{escape(line)}</span>'
            "</span>"
        )
        if len(self._pending) == self.MAX_PENDING:
            self._dropped += 1  # deque(maxlen) сам выбросит самую старую строку
        self._pending.append(html)
        if not self._flush_timer.isActive():
            self._flush_timer.start()

    def flush_pending(self) -> None:
        if not self._pending and not self._dropped:
            return
        bar = self.verticalScrollBar()
        follow = bar.value() >= bar.maximum() - 4
        if self._dropped:
            self.appendHtml(f'<span style="color:{theme.AMBER}">… пропущено строк: {self._dropped}</span>')
            self._dropped = 0
        while self._pending:
            self.appendHtml(self._pending.popleft())
        if follow:
            bar.setValue(bar.maximum())

    def clear_log(self) -> None:
        self._pending.clear()
        self._dropped = 0
        self.clear()

    def plain_text(self) -> str:
        self.flush_pending()
        return self.toPlainText()
