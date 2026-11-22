"""Виджеты окна: точка статуса, строка сервиса, кнопка навигации, журнал."""
from __future__ import annotations

import re
from datetime import datetime
from html import escape
from typing import Callable

from PyQt6.QtCore import QPointF, Qt, QTimer, QVariantAnimation, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QTextOption
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from app.ui import theme

_RUNNING = QVariantAnimation.State.Running


# ====================================================================== точка статуса
class StatusDot(QWidget):
    """Цветная точка. В промежуточных состояниях вокруг неё расходится кольцо."""

    def __init__(self, diameter: int = 8, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._diameter = diameter
        self._color = QColor(theme.IDLE)
        self._pending = False
        self._phase = 0.0
        self.setFixedSize(diameter + 12, diameter + 12)
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(1400)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setLoopCount(-1)
        self._anim.valueChanged.connect(self._on_phase)

    def set_state(self, color: str, pending: bool = False) -> None:
        self._color = QColor(color)
        self._pending = pending
        running = self._anim.state() == _RUNNING
        if pending and not running:
            self._anim.start()
        elif not pending and running:
            self._anim.stop()
            self._phase = 0.0
        self.update()

    def _on_phase(self, value: object) -> None:
        self._phase = float(value)  # type: ignore[arg-type]
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: ANN001
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        center = QPointF(self.width() / 2, self.height() / 2)
        radius = self._diameter / 2
        if self._pending:
            halo = QColor(self._color)
            halo.setAlphaF(0.45 * (1.0 - self._phase))
            painter.setBrush(halo)
            spread = radius + 5.0 * self._phase
            painter.drawEllipse(center, spread, spread)
        painter.setBrush(self._color)
        painter.drawEllipse(center, radius, radius)
        painter.end()


# ====================================================================== строка сервиса
class StatusRow(QWidget):
    """● Название / детали (адрес)            Состояние"""

    def __init__(self, name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 4, 0, 4)
        row.setSpacing(8)

        self._dot = StatusDot()
        row.addWidget(self._dot, 0, Qt.AlignmentFlag.AlignTop)

        texts = QVBoxLayout()
        texts.setSpacing(2)
        title = QLabel(name)
        title.setObjectName("ServiceName")
        self._detail = QLabel("")
        self._detail.setObjectName("ServiceDetail")
        self._detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        texts.addWidget(title)
        texts.addWidget(self._detail)
        row.addLayout(texts, 1)

        self._state = QLabel("")
        self._state.setObjectName("ServiceState")
        row.addWidget(self._state, 0, Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight)

    def set_state(self, text: str, color: str, pending: bool = False) -> None:
        self._dot.set_state(color, pending)
        self._state.setText(text)
        self._state.setStyleSheet(f"color: {color};")

    def set_detail(self, text: str) -> None:
        self._detail.setText(text)
        self._detail.setVisible(bool(text))


# ====================================================================== навигация
class NavButton(QPushButton):
    """Пункт сайдбара: текст слева, счётчик справа (например, ошибки в журнале)."""

    def __init__(self, text: str, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("Nav")
        self.setCheckable(True)
        self.setAutoExclusive(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(34)
        self._badge = QLabel(self)
        self._badge.setObjectName("Badge")
        self._badge.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._badge.hide()

    def set_badge(self, count: int) -> None:
        self._badge.setVisible(count > 0)
        if count:
            self._badge.setText(str(count) if count < 100 else "99+")
            self._badge.adjustSize()
            self._place_badge()

    def resizeEvent(self, event) -> None:  # noqa: ANN001
        super().resizeEvent(event)
        self._place_badge()

    def _place_badge(self) -> None:
        hint = self._badge.sizeHint()
        self._badge.setGeometry(self.width() - hint.width() - 10, (self.height() - hint.height()) // 2,
                                hint.width(), hint.height())


# ====================================================================== журнал
_ERR_RE = re.compile(r"✖|\bERR\b|\bERROR\b|Traceback|\bCRITICAL\b", re.IGNORECASE)
_WARN_RE = re.compile(r"⚠|\bWRN\b|\bWARN(?:ING)?\b", re.IGNORECASE)


class LogView(QPlainTextEdit):
    """Журнал с пакетной отрисовкой: поток строк от cloudflared не подвешивает окно.

    * строки копятся и добавляются раз в 80 мс;
    * хранится не больше MAX_LINES последних строк;
    * автопрокрутка только если пользователь и так внизу;
    * перед показом строка проходит через redactor (вырезает токен).
    """

    error_logged = pyqtSignal()

    MAX_LINES = 5000
    FLUSH_MS = 80
    MAX_BATCH = 400

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Log")
        self.setReadOnly(True)
        self.setUndoRedoEnabled(False)
        self.setMaximumBlockCount(self.MAX_LINES)
        self.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self.setPlaceholderText("Здесь появятся логи сервера и туннеля.")
        self._pending: list[tuple[str, str, str]] = []
        self._redact: Callable[[str], str] | None = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(self.FLUSH_MS)
        self._timer.timeout.connect(self._flush)

    def set_redactor(self, redact: Callable[[str], str]) -> None:
        self._redact = redact

    def append_line(self, source: str, line: str) -> None:
        if self._redact is not None:
            line = self._redact(line)
        self._pending.append((datetime.now().strftime("%H:%M:%S"), source, line))
        if _ERR_RE.search(line):
            self.error_logged.emit()
        if not self._timer.isActive():
            self._timer.start()

    def plain_text(self) -> str:
        return self.toPlainText().replace("\u00a0", " ")

    def clear_log(self) -> None:
        self._pending.clear()
        self.clear()

    def _flush(self) -> None:
        batch = self._pending[: self.MAX_BATCH]
        del self._pending[: self.MAX_BATCH]
        bar = self.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 4
        for stamp, source, line in batch:
            self.appendHtml(self._format(stamp, source, line))
        if at_bottom:
            bar.setValue(bar.maximum())
        if self._pending:
            self._timer.start()

    @staticmethod
    def _format(stamp: str, source: str, line: str) -> str:
        label, label_color = theme.LOG_SOURCES.get(source, (source, theme.TEXT_MUTED))
        if _ERR_RE.search(line):
            color = theme.ERR
        elif _WARN_RE.search(line):
            color = theme.WARN
        elif line.startswith("✔"):
            color = theme.OK
        elif source == "app":
            color = theme.TEXT
        else:
            color = theme.TEXT_MUTED
        pad = "&nbsp;" * max(1, 8 - len(label))
        return (
            f'<span style="color:{theme.TEXT_FAINT}">{stamp}</span>&nbsp;&nbsp;'
            f'<span style="color:{label_color}">{escape(label)}</span>{pad}'
            f'<span style="color:{color}">{escape(line)}</span>'
        )
