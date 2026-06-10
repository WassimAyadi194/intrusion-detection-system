"""
frontend/widgets/alerts/alert_feed.py

Scrollable, filterable alert list panel.
"""

import queue
import time

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QScrollArea, QSizePolicy, QStackedLayout
)
from PySide6.QtCore import Qt, QTimer

from frontend.theme import SPACING
from frontend.widgets.shared.helpers import _lbl, _panel_header, _scrollable
from frontend.widgets.shared.filter_bar import FilterBar
from frontend.widgets.alerts.alert_entry import AlertEntry

# Maximum number of alert rows kept in memory.
_MAX_ENTRIES = 100

# Alerts drained from the queue per timer tick.
_DRAIN_BATCH = 20

# Normalise only MEDIUM → MED; all other backend values are displayed as-is.
_SEV_NORMALISE = {"MEDIUM": "MED"}


class AlertFeed(QWidget):
    """Scrollable, filterable alert list panel."""

    def __init__(self, alert_queue: "queue.Queue | None" = None, parent=None):
        super().__init__(parent)
        self.setObjectName("dashPanel")

        self._alert_queue = alert_queue
        self._entries: list[AlertEntry] = []
        self._first_alert = True

        outer = QVBoxLayout(self)
        outer.setContentsMargins(
            SPACING["none"], SPACING["none"], SPACING["none"], SPACING["none"]
        )
        outer.setSpacing(SPACING["none"])

        outer.addWidget(_panel_header("ALERT FEED"))

        # Filter bar
        self._filter = FilterBar(
            placeholder="Filter by IP / host…",
            severities=["ALL", "CRITICAL", "HIGH", "MED", "LOW", "INFO"],
        )
        self._filter.combo.currentTextChanged.connect(self._apply_filter)
        self._filter.text_input.textChanged.connect(self._apply_filter)
        outer.addWidget(self._filter)

        # croll content: ONLY  AlertEntry rows live here

        self._inner = QWidget()
        self._inner.setObjectName("scrollInner")
        self._vbox = QVBoxLayout(self._inner)
        self._vbox.setContentsMargins(
            SPACING["none"], SPACING["sm"], SPACING["none"], SPACING["sm"]
        )
        self._vbox.setSpacing(SPACING["xs"])
        self._vbox.setAlignment(Qt.AlignmentFlag.AlignTop)

        self._scroll: QScrollArea = _scrollable(self._inner)
        self._scroll.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )

        # ── Overlay: scroll area + state labels via StackAll ─────────────────
        # QStackedLayout(StackAll) lets all layers occupy the same geometry.
        # The waiting/empty labels float visually above the scroll area without
        # ever entering _vbox — they have zero effect on scroll height math.
        overlay = QWidget()
        stacked = QStackedLayout(overlay)
        stacked.setStackingMode(QStackedLayout.StackingMode.StackAll)

        # Layer 0: scroll area — always fills the full area 
        stacked.addWidget(self._scroll)

        # Layer 1: "Waiting for traffic…" — visible until first alert arrives
        self._waiting_lbl = _lbl(
            "Waiting for traffic…", "waitingLabel", Qt.AlignmentFlag.AlignCenter
        )
        self._waiting_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        stacked.addWidget(self._waiting_lbl)

        # Layer 2: "No data for this host" — visible when filter matches nothing
        self._empty_lbl = _lbl(
            "No data for this host", "emptyLabel", Qt.AlignmentFlag.AlignCenter
        )
        self._empty_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._empty_lbl.setVisible(False)
        stacked.addWidget(self._empty_lbl)

        outer.addWidget(overlay, stretch=1)

        # Start queue drain timer only when a live queue was provided.
        if self._alert_queue is not None:
            self._timer = QTimer(self)
            self._timer.setInterval(50)  # ms
            self._timer.timeout.connect(self._drain_queue)
            self._timer.start()

        # Pruning timer: runs every 1 second to remove alerts older than 60s
        self._prune_timer = QTimer(self)
        self._prune_timer.setInterval(1000)
        self._prune_timer.timeout.connect(self._prune_old_alerts)
        self._prune_timer.start()

    # ------------------------------------------------------------------
    # Queue drain — called every 50 ms by QTimer (UI thread only)
    # ------------------------------------------------------------------

    def _drain_queue(self) -> None:
        drained = 0
        while drained < _DRAIN_BATCH:
            try:
                alert = self._alert_queue.get_nowait()
            except queue.Empty:
                break
            self._push_alert_row(alert)
            drained += 1

        if drained > 0:
            # Defer filter + scroll until after Qt has flushed layout recalc.
            QTimer.singleShot(0, self._apply_filter)
            QTimer.singleShot(0, self._scroll_to_top)

    # ------------------------------------------------------------------
    # Alert ingestion
    # ------------------------------------------------------------------

    def _push_alert_row(self, alert: dict) -> None:
        """Prepend a new AlertEntry row."""
        severity_raw = alert.get("severity", "LOW")
        severity = _SEV_NORMALISE.get(severity_raw, severity_raw)

        ts_epoch = alert.get("timestamp", time.time())
        try:
            ts_str = time.strftime("%H:%M:%S", time.localtime(float(ts_epoch)))
        except (ValueError, TypeError):
            ts_str = "??:??:??"

        host = alert.get("src", "unknown")
        description = alert.get("message", "")

        entry = AlertEntry(ts_str, severity, host, description, parent=self._inner)
        entry._ts_epoch = float(ts_epoch)
        self._entries.insert(0, entry)

        # Hide the waiting overlay permanently on first real alert.
        if self._first_alert:
            self._waiting_lbl.setVisible(False)
            self._first_alert = False

        # Insert at position 0 — _vbox contains ONLY AlertEntry rows, so
        # index 0 is always the top of the visible list. No state labels
        # exist in this layout to offset the index.
        self._vbox.insertWidget(0, entry)

        # Cap to avoid unbounded memory growth.
        if len(self._entries) > _MAX_ENTRIES:
            oldest = self._entries.pop()
            self._vbox.removeWidget(oldest)
            oldest.deleteLater()

    def _scroll_to_top(self) -> None:
        """Scroll to top so the newest alert is visible.

        Deferred via QTimer.singleShot(0) so Qt has finished layout recalc
        and the scrollbar range is correct before we move it.
        """
        vsb = self._scroll.verticalScrollBar()
        vsb.setValue(vsb.minimum())

    def _prune_old_alerts(self) -> None:
        """Remove alerts older than 60 seconds to match the KPI window."""
        now = time.time()
        cutoff = now - 60.0
        pruned = False

        while self._entries and getattr(self._entries[-1], "_ts_epoch", now) < cutoff:
            oldest = self._entries.pop()
            self._vbox.removeWidget(oldest)
            oldest.deleteLater()
            pruned = True

        if pruned:
            self._apply_filter()

    # ------------------------------------------------------------------
    # Filter
    # ------------------------------------------------------------------

    def _apply_filter(self) -> None:
        sev = self._filter.combo.currentText()
        host = self._filter.text_input.text().strip().lower()
        visible = 0
        for entry in self._entries:
            ok = ((sev == "ALL") or (entry._severity == sev)) and \
                 ((not host) or (host in entry._host.lower()))
            entry.setVisible(ok)
            visible += ok

        has_entries = len(self._entries) > 0
        self._empty_lbl.setVisible(visible == 0 and has_entries)
        # _waiting_lbl is managed solely by _push_alert_row — never toggled here.