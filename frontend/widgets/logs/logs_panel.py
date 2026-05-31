"""
frontend/widgets/logs/logs_panel.py

Collapsible system logs panel.

Animation is handled externally by the parent (DashboardPage) via the
panel_toggled signal — the parent animates this widget's geometry so the
toggle button is always pinned to a fixed y-position regardless of state.
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton
from PySide6.QtCore import QTimer, Qt, Signal

from frontend.theme import SPACING, LAYOUT_SIZES
from frontend.widgets.shared.helpers import _scrollable
from frontend.widgets.shared.filter_bar import FilterBar
from frontend.widgets.logs.log_entry import LogEntry

import queue

_DRAIN_BATCH = 20
_MAX_ENTRIES = 200


class LogsPanel(QWidget):

    panel_toggled = Signal(bool)   # True = expanding, False = collapsing

    _LOGS = []

    def __init__(self, log_queue=None, parent=None):
        super().__init__(parent)
        self._log_queue = log_queue
        self._filter_text = ""
        self.setObjectName("logsPanel")
        self._expanded = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(
            SPACING["none"], SPACING["none"], SPACING["none"], SPACING["none"]
        )
        outer.setSpacing(SPACING["none"])

        # ── Body ─────────────────────────────────────────────────────────────
        # Placed FIRST (above toggle) so it grows upward as the panel expands.
        # Starts hidden; the parent shows it before starting the expand anim.
        self._body = QWidget()
        self._body.setObjectName("logsBody")
        self._body.hide()

        body_layout = QVBoxLayout(self._body)
        body_layout.setContentsMargins(
            SPACING["none"], SPACING["none"], SPACING["none"], SPACING["none"]
        )
        body_layout.setSpacing(SPACING["none"])

        log_filter = FilterBar(placeholder="Search logs…")
        log_filter.text_input.textChanged.connect(self._on_filter_changed)
        body_layout.addWidget(log_filter)

        inner = QWidget()
        inner.setObjectName("scrollInner")
        self._vbox = QVBoxLayout(inner)
        self._vbox.setContentsMargins(
            SPACING["none"], SPACING["xs"], SPACING["none"], SPACING["xs"]
        )
        self._vbox.setSpacing(SPACING["none"])
        self._vbox.setAlignment(Qt.AlignmentFlag.AlignTop)

        self._entries: list[LogEntry] = []
        for ts, lvl, module, msg in self._LOGS:
            entry = LogEntry(ts, lvl, f"[{module}] {msg}")
            self._entries.append(entry)
            self._vbox.addWidget(entry)

        self._scroll = _scrollable(inner)
        self._scroll.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        body_layout.addWidget(self._scroll, stretch=1)

        # stretch=1 so body fills all space above the toggle button
        outer.addWidget(self._body, stretch=1)

        # ── Toggle button ─────────────────────────────────────────────────────
        # Placed LAST so it always sits at the bottom of the widget.
        self._toggle_btn = QPushButton("▼  SHOW LOGS")
        self._toggle_btn.setObjectName("logsToggleBtn")
        self._toggle_btn.setFixedHeight(LAYOUT_SIZES["panel_header_h"])
        self._toggle_btn.clicked.connect(self._toggle)
        outer.addWidget(self._toggle_btn)

        # ── Log queue polling ─────────────────────────────────────────────────
        if self._log_queue is not None:
            self._poll_timer = QTimer(self)
            self._poll_timer.setInterval(100)
            self._poll_timer.timeout.connect(self._drain_queue)
            self._poll_timer.start()

    # ------------------------------------------------------------------
    # Toggle state — text update only; geometry is handled by parent
    # ------------------------------------------------------------------

    def _toggle(self) -> None:
        self._expanded = not self._expanded
        self._toggle_btn.setText(
            "▲  HIDE LOGS" if self._expanded else "▼  SHOW LOGS"
        )
        if self._expanded:
            # Show body before the expand animation starts so it is visible
            # as soon as any height is given to it by the parent.
            self._body.show()
        self.panel_toggled.emit(self._expanded)

    def on_collapse_finished(self) -> None:
        """Called by DashboardPage when the collapse animation completes."""
        self._body.hide()

    # ------------------------------------------------------------------
    # Queue drain
    # ------------------------------------------------------------------

    def _drain_queue(self) -> None:
        """Pull up to _DRAIN_BATCH items from the queue per tick (non-blocking)."""
        if self._log_queue is None:
            return
        drained = 0
        while drained < _DRAIN_BATCH:
            try:
                ts, lvl, module, msg = self._log_queue.get_nowait()
            except queue.Empty:
                break
            
            if lvl == "CRITICAL" and "tshark" in msg.lower():
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.critical(self, "Engine Error", msg)
                
            if len(self._entries) >= _MAX_ENTRIES:
                oldest = self._entries.pop()        # oldest is always at end of list
                self._vbox.removeWidget(oldest)
                oldest.hide()
                oldest.deleteLater()
            entry = LogEntry(ts, lvl, f"[{module}] {msg}", parent=self._vbox.parentWidget())
            self._entries.insert(0, entry)          # newest at front of list
            self._vbox.insertWidget(0, entry)       # newest at top of layout
            drained += 1

        if drained > 0:
            QTimer.singleShot(0, self._apply_filter)
        
    # ------------------------------------------------------------------
    # Filter
    # ------------------------------------------------------------------

    def _on_filter_changed(self, text: str) -> None:
        """Called when the user types in the filter bar."""
        if not isinstance(text, str):
            text = ""
        self._filter_text = text.strip().lower()
        self._apply_filter()

    def _apply_filter(self) -> None:
        """Show/hide entries based on the current filter text."""
        text = self._filter_text
        for entry in self._entries:
            entry.setVisible((not text) or (text in entry._message.lower()))