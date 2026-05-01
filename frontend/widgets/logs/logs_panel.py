"""
frontend/widgets/logs/logs_panel.py

Collapsible system logs panel – sits below the main panels.
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton
from PySide6.QtCore import QPropertyAnimation, QEasingCurve, QTimer

from frontend.theme import SPACING, LAYOUT_SIZES
from frontend.widgets.shared.helpers import _scrollable
from frontend.widgets.shared.filter_bar import FilterBar
from frontend.widgets.logs.log_entry import LogEntry

import queue

_DRAIN_BATCH = 20
_MAX_ENTRIES = 200


class LogsPanel(QWidget):
    """Collapsible system logs panel – sits below the main panels."""

    _LOGS = [

    ]

    def __init__(self, log_queue=None, parent=None):
        super().__init__(parent)
        self._log_queue = log_queue
        self.setObjectName("logsPanel")
        self._expanded = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(
            SPACING["none"], SPACING["none"], SPACING["none"], SPACING["none"]
        )
        outer.setSpacing(SPACING["none"])

        # Toggle button
        self._toggle_btn = QPushButton("▼  SHOW LOGS")
        self._toggle_btn.setObjectName("logsToggleBtn")
        self._toggle_btn.setFixedHeight(LAYOUT_SIZES["panel_header_h"])
        self._toggle_btn.clicked.connect(self._toggle)
        outer.addWidget(self._toggle_btn)

        # Collapsible body (starts collapsed)
        self._body = QWidget()
        self._body.setObjectName("logsBody")
        self._body.setMaximumHeight(0)

        body_layout = QVBoxLayout(self._body)
        body_layout.setContentsMargins(
            SPACING["none"], SPACING["none"], SPACING["none"], SPACING["none"]
        )
        body_layout.setSpacing(SPACING["none"])

        log_filter = FilterBar(placeholder="Search logs…")
        log_filter.text_input.textChanged.connect(self._apply_filter)
        body_layout.addWidget(log_filter)

        inner = QWidget()
        inner.setObjectName("scrollInner")
        self._vbox = QVBoxLayout(inner)
        self._vbox.setContentsMargins(
            SPACING["none"], SPACING["xs"], SPACING["none"], SPACING["xs"]
        )
        self._vbox.setSpacing(SPACING["none"])

        self._entries: list[LogEntry] = []
        for ts, lvl, module, msg in self._LOGS:
            entry = LogEntry(ts, lvl, f"[{module}] {msg}")
            self._entries.append(entry)
            self._vbox.addWidget(entry)
        self._vbox.addStretch()

        body_layout.addWidget(_scrollable(inner), stretch=1)
        outer.addWidget(self._body)

        # Start polling timer only when a queue is provided
        if self._log_queue is not None:
            self._poll_timer = QTimer(self)
            self._poll_timer.setInterval(100)  # drain every 100 ms
            self._poll_timer.timeout.connect(self._drain_queue)
            self._poll_timer.start()

    def _drain_queue(self) -> None:
        """
        Pull up to _DRAIN_BATCH items from the queue per tick (non-blocking).
        
        It is non-blocking per item, not per loop.
        The loop itself is bounded, not time-bounded
        """
        if self._log_queue is None:
            return

        drained = 0
        while drained < _DRAIN_BATCH:
            try:
                ts, lvl, module, msg = self._log_queue.get_nowait()
            except queue.Empty:
                break

            # --- Prompt 2: enforce hard cap, evict oldest (tail) first ---
            if len(self._entries) >= _MAX_ENTRIES:
                oldest = self._entries.pop()          # O(1) — oldest is at tail
                self._vbox.removeWidget(oldest)
                oldest.deleteLater()

            # --- Prompt 1: prepend so newest entry appears at the top ---
            entry = LogEntry(ts, lvl, f"[{module}] {msg}")
            self._entries.insert(0, entry)            # keep list in sync
            self._vbox.insertWidget(0, entry)         # index 0 = visual top
            drained += 1

        if drained > 0:
            # Defer filter re-evaluation until Qt has flushed layout recalc
            QTimer.singleShot(0, lambda: self._apply_filter(""))

    def _toggle(self) -> None:
        self._expanded = not self._expanded
        target = LAYOUT_SIZES["logs_panel_h"] if self._expanded else SPACING["none"]
        self._toggle_btn.setText(
            "▲  HIDE LOGS" if self._expanded else "▼  SHOW LOGS"
        )

        # Animate maximumHeight (cap) and minimumHeight (floor) together.
        # Driving only maximumHeight is not enough: because LogsPanel has no
        # stretch factor in the dashboard QVBoxLayout, Qt never allocates it
        # extra room.  Raising minimumHeight forces the layout to reserve the
        # full target height regardless of stretch.
        anim_max = QPropertyAnimation(self._body, b"maximumHeight", self)
        anim_max.setDuration(200)
        anim_max.setStartValue(self._body.maximumHeight())
        anim_max.setEndValue(target)
        anim_max.setEasingCurve(QEasingCurve.Type.InOutQuad)

        anim_min = QPropertyAnimation(self._body, b"minimumHeight", self)
        anim_min.setDuration(200)
        anim_min.setStartValue(self._body.minimumHeight())
        anim_min.setEndValue(target)
        anim_min.setEasingCurve(QEasingCurve.Type.InOutQuad)

        anim_max.start()
        anim_min.start()
        self._anim_max = anim_max  # keep references alive
        self._anim_min = anim_min

    def _apply_filter(self, text: str = "") -> None:
        if not isinstance(text, str):
            text = ""

        text = text.strip().lower()

        for entry in self._entries:
            entry.setVisible((not text) or (text in entry._message.lower()))