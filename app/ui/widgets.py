"""Core status, navigation, and log-view widgets (Linear + Docker Desktop theme-aware)."""
from __future__ import annotations

import re
from datetime import datetime
from html import escape
from typing import Callable

from PyQt6.QtCore import QPointF, QSize, Qt, QTimer, QVariantAnimation, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QTextOption
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from app.ui import icons, theme
from app.ui.i18n import tr

_RUNNING = QVariantAnimation.State.Running

_ERR_RE = re.compile(r"✖|\bERR\b|\bERROR\b|Traceback|\bCRITICAL\b", re.IGNORECASE)
_WARN_RE = re.compile(r"⚠|\bWRN\b|\bWARN(?:ING)?\b", re.IGNORECASE)


def repolish(widget: QWidget) -> None:
    """Re-apply Qt stylesheet after dynamic property changes."""
    style = widget.style()
    if style is not None:
        style.unpolish(widget)
        style.polish(widget)
    widget.update()


class StatusDot(QWidget):
    """Colored status dot with a subtle pulse ring only during pending transitions."""

    def __init__(self, diameter: int = 8, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._diameter = diameter
        self._color = QColor(theme.IDLE)
        self._pending = False
        self._phase = 0.0
        self.setFixedSize(diameter + 10, diameter + 10)
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
            halo.setAlphaF(0.40 * (1.0 - self._phase))
            painter.setBrush(halo)
            spread = radius + 4.5 * self._phase
            painter.drawEllipse(center, spread, spread)
        painter.setBrush(self._color)
        painter.drawEllipse(center, radius, radius)
        painter.end()


class StatusRow(QWidget):
    """Service health row: dot + service title/detail on left, status label on right."""

    def __init__(self, name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 4, 0, 4)
        row.setSpacing(8)

        self._dot = StatusDot()
        row.addWidget(self._dot, 0, Qt.AlignmentFlag.AlignTop)

        texts = QVBoxLayout()
        texts.setSpacing(2)
        self._title = QLabel(name)
        self._title.setObjectName("ServiceName")
        self._detail = QLabel("")
        self._detail.setObjectName("ServiceDetail")
        self._detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        texts.addWidget(self._title)
        texts.addWidget(self._detail)
        row.addLayout(texts, 1)

        self._state = QLabel("")
        self._state.setObjectName("ServiceState")
        row.addWidget(self._state, 0, Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight)

    def set_title(self, text: str) -> None:
        self._title.setText(text)

    def set_state(self, text: str, color: str, pending: bool = False) -> None:
        self._dot.set_state(color, pending)
        self._state.setText(text)
        self._state.setStyleSheet(f"color: {color};")

    def set_detail(self, text: str) -> None:
        self._detail.setText(text)
        self._detail.setVisible(bool(text))


class NavButton(QPushButton):
    """Sidebar navigation item with vector icon, collapsible label, and optional tag/badge."""

    def __init__(
        self,
        text: str,
        icon_name: str = "home",
        tag_text: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(text, parent)
        self._full_text = text
        self._icon_name = icon_name
        self._tag_text = tag_text
        self._collapsed = False
        self._badge_count = 0

        self.setObjectName("Nav")
        self.setCheckable(True)
        self.setAutoExclusive(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(32)
        self.setIconSize(QSize(15, 15))

        self._badge = QLabel(self)
        self._badge.setObjectName("Badge")
        self._badge.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._badge.hide()

        self._tag = QLabel(tag_text, self)
        self._tag.setObjectName("Pill")
        self._tag.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        if not tag_text:
            self._tag.hide()

        self.toggled.connect(lambda _checked: self.refresh_theme())
        self.refresh_theme()

    def set_label(self, text: str) -> None:
        self._full_text = text
        self.setText("" if self._collapsed else text)

    def set_collapsed(self, collapsed: bool) -> None:
        self._collapsed = collapsed
        self.setProperty("collapsed", collapsed)
        self.setText("" if collapsed else self._full_text)
        self._tag.setVisible(bool(self._tag_text) and not collapsed)
        repolish(self)
        self._place_decorations()

    def set_badge(self, count: int) -> None:
        self._badge_count = count
        self._badge.setVisible(count > 0)
        if count:
            self._badge.setText(str(count) if count < 100 else "99+")
            self._badge.adjustSize()
            self._place_decorations()

    def refresh_theme(self) -> None:
        color = theme.ACCENT if self.isChecked() else theme.TEXT_MUTED
        self.setIcon(icons.vector_icon(self._icon_name, color, 15))
        if self._tag_text and not self._collapsed:
            self.setStyleSheet("QPushButton#Nav { padding-right: 54px; }")
        else:
            self.setStyleSheet("")

    def showEvent(self, event) -> None:  # noqa: ANN001
        super().showEvent(event)
        self._place_decorations()

    def resizeEvent(self, event) -> None:  # noqa: ANN001
        super().resizeEvent(event)
        self._place_decorations()

    def _place_decorations(self) -> None:
        if not self._badge.isHidden():
            self._badge.adjustSize()
            hint = self._badge.sizeHint()
            x = max(2, self.width() - hint.width() - (4 if self._collapsed else 8))
            y = 3 if self._collapsed else (self.height() - hint.height()) // 2
            self._badge.setGeometry(x, y, hint.width(), hint.height())
        if not self._tag.isHidden():
            self._tag.adjustSize()
            hint = self._tag.sizeHint()
            self._tag.setGeometry(
                max(2, self.width() - hint.width() - 8),
                (self.height() - hint.height()) // 2,
                hint.width(),
                hint.height(),
            )


class LogView(QPlainTextEdit):
    """Buffered, filterable, theme-aware log viewer with secret redaction."""

    error_logged = pyqtSignal()
    counts_changed = pyqtSignal(int, int)

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
        self.setPlaceholderText(tr("logs.placeholder"))

        self._records: list[tuple[str, str, str]] = []
        self._pending: list[tuple[str, str, str]] = []
        self._redact: Callable[[str], str] | None = None
        self._source_filter = "all"
        self._level_filter = "all"
        self._query = ""
        self._auto_scroll = True

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(self.FLUSH_MS)
        self._timer.timeout.connect(self._flush)

    def set_redactor(self, redact: Callable[[str], str]) -> None:
        self._redact = redact

    def set_auto_scroll(self, enabled: bool) -> None:
        self._auto_scroll = enabled

    def set_filters(
        self,
        *,
        source: str | None = None,
        level: str | None = None,
        query: str | None = None,
    ) -> None:
        if source is not None:
            self._source_filter = source
        if level is not None:
            self._level_filter = level
        if query is not None:
            self._query = query.strip().lower()
        self.re_render()

    def append_line(self, source: str, line: str) -> None:
        if self._redact is not None:
            line = self._redact(line)
        record = (datetime.now().strftime("%H:%M:%S"), source, line)
        self._records.append(record)
        if len(self._records) > self.MAX_LINES:
            del self._records[: len(self._records) - self.MAX_LINES]
        self._pending.append(record)
        if _ERR_RE.search(line):
            self.error_logged.emit()
        if not self._timer.isActive():
            self._timer.start()

    def plain_text(self) -> str:
        return self.toPlainText().replace("\u00a0", " ")

    def clear_log(self) -> None:
        self._pending.clear()
        self._records.clear()
        self.clear()
        self.counts_changed.emit(0, 0)

    def records_count(self) -> tuple[int, int]:
        shown = sum(1 for r in self._records if self._matches(r))
        return shown, len(self._records)

    def flush_now(self) -> None:
        if self._pending:
            self._flush()

    def re_render(self) -> None:
        self._pending.clear()
        self.setPlaceholderText(tr("logs.placeholder"))
        self.clear()
        matched = [r for r in self._records if self._matches(r)]
        if matched:
            self.appendHtml("<br>".join(self._format(*r) for r in matched))
            if self._auto_scroll:
                bar = self.verticalScrollBar()
                bar.setValue(bar.maximum())
        self.counts_changed.emit(len(matched), len(self._records))

    def _matches(self, record: tuple[str, str, str]) -> bool:
        _stamp, source, line = record
        if self._source_filter != "all" and source != self._source_filter:
            return False
        if self._level_filter == "err" and not _ERR_RE.search(line):
            return False
        if self._level_filter == "warn" and not (_ERR_RE.search(line) or _WARN_RE.search(line)):
            return False
        if self._query and self._query not in line.lower() and self._query not in source.lower():
            return False
        return True

    def _flush(self) -> None:
        batch = self._pending[: self.MAX_BATCH]
        del self._pending[: self.MAX_BATCH]
        bar = self.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 4
        filtered = [r for r in batch if self._matches(r)]
        if filtered:
            self.appendHtml("<br>".join(self._format(*r) for r in filtered))
        if self._auto_scroll and at_bottom:
            bar.setValue(bar.maximum())
        shown, total = self.records_count()
        self.counts_changed.emit(shown, total)
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
            f'<span style="color:{label_color}; font-weight:600">{escape(label)}</span>{pad}'
            f'<span style="color:{color}">{escape(line)}</span>'
        )
