"""
frontend/widgets/hosts/host_metrics.py

Right panel – filterable, sortable host metric cards driven by HostRefresher.

"""

from __future__ import annotations

import subprocess
import sys
import os

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QMessageBox, QComboBox,
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal

from frontend.theme import SPACING
from frontend.widgets.shared.helpers import _lbl, _panel_header, _scrollable
from frontend.widgets.shared.filter_bar import FilterBar
from frontend.widgets.hosts.host_card import HostCard
from frontend.widgets.hosts.host_refresher import HostRefresher
from baseline.baseline_reader import get_all_baselines
from logs.ids_logger import get_logger

_log = get_logger(__name__)

_RETRAIN_COOLDOWN_S = 20   # seconds the button stays disabled after a click

# Project root — three levels up from this file:
#   frontend/widgets/hosts/  →  frontend/widgets/  →  frontend/  →  <root>
_PROJECT_ROOT = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")
)

# Sort options: display label → snapshot data key (or sentinel)
_SORT_OPTIONS: list[tuple[str, str]] = [
    ("NONE",        "none"),
    ("PKT/S",       "pkt_rate"),
    ("CONNECTIONS", "active_connections"),
    ("ANOMALY/S",   "anomaly_count"),
    ("SEVERITY",    "anomaly_level"),
    ("KNOWN",       "novelty"),
]

# Numeric rank for SEVERITY — higher rank = shown first (descending)
_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MED":      2,
    "MEDIUM":   2,
    "LOW":      1,
    "NONE":     0,
    "":         0,
}

# Novelty sort: KNOWN > RECURRING > NEW > LOOPBACK
_NOVELTY_RANK: dict[str, int] = {
    "KNOWN":     3,
    "RECURRING": 2,
    "NEW":       1,
    "LOOPBACK":  0,
}


# ══════════════════════════════════════════════════════════════════════════════
# Worker thread — keeps the subprocess off the main (GUI) thread
# ══════════════════════════════════════════════════════════════════════════════

class _RetrainWorker(QThread):
    """Run `python -m baseline.baseline_trainer` in a background thread.

    Signals
    -------
    done(success: bool, message: str)
        Emitted back on the main thread once the subprocess exits.
    """

    done: Signal = Signal(bool, str)

    def run(self) -> None:
        _log.info("Baseline retraining started.")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "baseline.baseline_trainer"],
                capture_output=True,
                text=True,
                cwd=_PROJECT_ROOT,
            )
        except Exception as exc:  # noqa: BLE001
            msg = f"Failed to launch baseline trainer: {exc}"
            _log.error(msg)
            self.done.emit(False, msg)
            return

        if result.returncode == 0:
            _log.info("Baseline retraining completed successfully.")
            self.done.emit(True, "Baseline retrained successfully.")
        else:
            stderr = (result.stderr or "").strip()
            if len(stderr) > 400:
                stderr = "\u2026" + stderr[-400:].lstrip()
            _log.error(
                "Baseline retraining failed (rc=%d):\n%s",
                result.returncode,
                stderr,
            )
            self.done.emit(
                False,
                stderr or f"Process exited with code {result.returncode}.",
            )


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _build_display(data: dict) -> tuple[list[tuple[str, str]], str]:
    """Convert a single host_metrics_snapshot() entry into HostCard display args."""
    pkt_rate      = data.get("pkt_rate", 0)
    conns         = data.get("active_connections", 0)
    anomaly_count = data.get("anomaly_count", 0)
    anomaly_level = (data.get("anomaly_level") or "NONE").upper()
    novelty       = data.get("novelty", "")

    metrics: list[tuple[str, str]] = [
        ("PKT/S",     str(round(pkt_rate, 1))),
        ("CONN",      str(conns)),
        ("ANOMALY/S", str(anomaly_count)),
        ("SEVERITY",  anomaly_level),
    ]
    return metrics, novelty


def _sort_key(sort_field: str, data: dict):
    """Return a sort key for *data* given the active sort field.

    Always descending — callers should negate or use reverse=True.
    """
    if sort_field == "pkt_rate":
        return float(data.get("pkt_rate", 0) or 0)
    if sort_field == "active_connections":
        return int(data.get("active_connections", 0) or 0)
    if sort_field == "anomaly_count":
        return int(data.get("anomaly_count", 0) or 0)
    if sort_field == "anomaly_level":
        raw = (data.get("anomaly_level") or "").upper()
        return _SEVERITY_RANK.get(raw, 0)
    if sort_field == "novelty":
        raw = (data.get("novelty") or "LOOPBACK").upper()
        return _NOVELTY_RANK.get(raw, 0)
    return 0   # "none" — stable insertion order


# ══════════════════════════════════════════════════════════════════════════════
# Sort bar widget
# ══════════════════════════════════════════════════════════════════════════════

class _SortBar(QWidget):
    """Thin bar with a 'SORT BY' label and a QComboBox — mirrors FilterBar styling."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("filterBar")          # reuse filterBar QSS

        row = QHBoxLayout(self)
        row.setContentsMargins(
            SPACING["lg"], SPACING["sm"], SPACING["lg"], SPACING["sm"]
        )
        row.setSpacing(SPACING["md"])

        lbl = _lbl("SORT BY", "panelSubtitle")
        row.addWidget(lbl)

        self._combo = QComboBox()
        self._combo.setObjectName("filterCombo")  # reuse filterCombo QSS
        for label, _ in _SORT_OPTIONS:
            self._combo.addItem(label)
        row.addWidget(self._combo, stretch=1)

    @property
    def combo(self) -> QComboBox:
        return self._combo

    def current_field(self) -> str:
        """Return the snapshot data key for the currently selected sort option."""
        idx = self._combo.currentIndex()
        return _SORT_OPTIONS[idx][1]


# ══════════════════════════════════════════════════════════════════════════════
# HostMetricsArea
# ══════════════════════════════════════════════════════════════════════════════

class HostMetricsArea(QWidget):
    """Right panel – filterable, sortable host metric cards with baseline indicators.

    Public API
    ----------
    set_engine(engine)  — attach a live DetectionEngine; pass None to detach.
    """

    def __init__(self, engine=None, parent=None):
        super().__init__(parent)
        self.setObjectName("dashPanel")

        # ── Layout skeleton ───────────────────────────────────────────────
        outer = QVBoxLayout(self)
        outer.setContentsMargins(
            SPACING["none"], SPACING["none"], SPACING["none"], SPACING["none"]
        )
        outer.setSpacing(SPACING["none"])

        outer.addWidget(_panel_header("HOST METRICS"))

        # ── Retrain Baseline button ────────────────────────────────────────
        self._retrain_btn = QPushButton("\u27f3  RETRAIN BASELINE")
        self._retrain_btn.setObjectName("retrainBaselineBtn")
        self._retrain_btn.clicked.connect(self._on_retrain_clicked)
        outer.addWidget(self._retrain_btn)

        # Cooldown countdown
        self._retrain_remaining: int = 0
        self._retrain_timer = QTimer(self)
        self._retrain_timer.setInterval(1000)
        self._retrain_timer.timeout.connect(self._retrain_tick)

        # Worker reference — kept alive until the thread finishes
        self._worker: _RetrainWorker | None = None

        # ── Filter + Sort bar row (50 / 50) ──────────────────────────────
        controls_row = QHBoxLayout()
        controls_row.setContentsMargins(
            SPACING["none"], SPACING["none"], SPACING["none"], SPACING["none"]
        )
        controls_row.setSpacing(SPACING["none"])

        self._filter = FilterBar(placeholder="Filter by host\u2026")
        self._filter.text_input.textChanged.connect(self._apply_filter)
        controls_row.addWidget(self._filter, stretch=1)

        self._sort_bar = _SortBar()
        self._sort_bar.combo.currentIndexChanged.connect(self._on_sort_changed)
        controls_row.addWidget(self._sort_bar, stretch=1)

        outer.addLayout(controls_row)

        # ── Scrollable card area ──────────────────────────────────────────
        inner = QWidget()
        inner.setObjectName("scrollInner")
        self._vbox = QVBoxLayout(inner)
        self._vbox.setContentsMargins(
            SPACING["md"], SPACING["md"], SPACING["md"], SPACING["md"]
        )
        self._vbox.setSpacing(SPACING["md"])
        self._vbox.setAlignment(Qt.AlignmentFlag.AlignTop)

        # "No data for this host" — shown when the filter matches nothing.
        self._empty_lbl: QLabel = _lbl(
            "No data for this host", "emptyLabel", Qt.AlignmentFlag.AlignCenter
        )
        self._empty_lbl.setVisible(False)
        self._vbox.addWidget(self._empty_lbl)

        # "Engine not running" banner — shown when no engine is attached.
        self._no_engine_lbl: QLabel = _lbl(
            "Engine not running", "emptyLabel", Qt.AlignmentFlag.AlignCenter
        )
        self._no_engine_lbl.setVisible(engine is None)
        self._vbox.addWidget(self._no_engine_lbl)

        outer.addWidget(_scrollable(inner), stretch=1)

        # ── State ─────────────────────────────────────────────────────────
        # card registry: host_ip → HostCard
        self._cards: dict[str, HostCard] = {}

        # Last raw snapshot — kept so re-sorting works without a new tick.
        self._last_snapshot: dict[str, dict] = {}

        # Baseline table loaded once per engine-attach, not per tick.
        self._baseline_cache: dict[str, dict] = {}

        # ── Live pipeline ─────────────────────────────────────────────────
        self._refresher = HostRefresher(engine, interval_ms=1000, parent=self)
        self._refresher.refreshed.connect(self._on_snapshot)
        if engine is not None:
            self._baseline_cache = get_all_baselines()
            self._refresher.start()

    def set_engine(self, engine) -> None:
        """Attach or detach the live DetectionEngine."""
        self._refresher.stop()
        self._refresher.set_engine(engine)

        if engine is not None:
            self._baseline_cache = get_all_baselines()
            self._no_engine_lbl.setVisible(False)
            self._refresher.start()
        else:
            self._no_engine_lbl.setVisible(True)

    # ------------------------------------------------------------------
    # Retrain Baseline button
    # ------------------------------------------------------------------

    def _on_retrain_clicked(self) -> None:
        """Disable the button, start the cooldown timer, and launch the worker."""
        self._retrain_btn.setEnabled(False)
        self._retrain_remaining = _RETRAIN_COOLDOWN_S
        self._retrain_btn.setText(
            f"\u27f3  RETRAIN BASELINE  ({self._retrain_remaining}s)"
        )
        self._retrain_timer.start()

        self._worker = _RetrainWorker(parent=self)
        self._worker.done.connect(self._on_retrain_done)
        self._worker.start()

    def _retrain_tick(self) -> None:
        """Decrement the visible countdown label once per second."""
        self._retrain_remaining -= 1
        if self._retrain_remaining <= 0:
            self._retrain_timer.stop()
            self._retrain_btn.setEnabled(True)
            self._retrain_btn.setText("\u27f3  RETRAIN BASELINE")
        else:
            self._retrain_btn.setText(
                f"\u27f3  RETRAIN BASELINE  ({self._retrain_remaining}s)"
            )

    def _on_retrain_done(self, success: bool, message: str) -> None:
        """Qt-safe slot — runs on the main thread via signal delivery."""
        if success:
            QMessageBox.information(self, "Baseline Retraining", message)
        else:
            QMessageBox.warning(self, "Baseline Retraining Failed", message)

    # ------------------------------------------------------------------
    # Snapshot handler — connected to HostRefresher.refreshed
    # ------------------------------------------------------------------

    def _on_snapshot(self, snapshot: dict) -> None:
        """Receive a fresh host_metrics_snapshot() payload and update the UI."""
        # Incrementally update so departed/frozen hosts retain their sort state
        for k, v in snapshot.items():
            self._last_snapshot[k] = v

        # Create / update cards
        for host_ip, data in snapshot.items():
            metrics, novelty = _build_display(data)
            b_data = self._baseline_cache.get(host_ip, {})

            if host_ip in self._cards:
                self._cards[host_ip].update(metrics, b_data, novelty)
            else:
                card = HostCard(host_ip, metrics, b_data, novelty)
                self._cards[host_ip] = card
                self._vbox.addWidget(card)   # order fixed up by _reorder_cards

        # We intentionally do not remove departed hosts so the feed acts like
        # the alert feed (freezing when stopped and keeping historical entries).

        self._reorder_cards()
        self._apply_filter()

    # ------------------------------------------------------------------
    # Sort
    # ------------------------------------------------------------------

    def _on_sort_changed(self) -> None:
        """Called when the user picks a new sort option."""
        self._reorder_cards()
        self._apply_filter()

    def _reorder_cards(self) -> None:
        """Re-arrange card widgets in the layout according to the active sort key.

        The two state labels (_empty_lbl, _no_engine_lbl) live at fixed
        positions 0 and 1 inside _vbox.  Cards are always inserted after them.
        """
        if not self._cards:
            return

        field = self._sort_bar.current_field()

        if field == "none":
            # Preserve insertion (arrival) order — nothing to reorder.
            ordered_ips = list(self._cards.keys())
        else:
            ordered_ips = sorted(
                self._cards.keys(),
                key=lambda ip: _sort_key(field, self._last_snapshot.get(ip, {})),
                reverse=True,   # descending: highest value at top
            )

        # Re-insert cards after the two state labels (indices 0, 1).
        _LABEL_COUNT = 2
        for position, ip in enumerate(ordered_ips):
            self._vbox.insertWidget(_LABEL_COUNT + position, self._cards[ip])

    # ------------------------------------------------------------------
    # Filter
    # ------------------------------------------------------------------

    def _apply_filter(self) -> None:
        """Show/hide cards that match the current filter text."""
        text = self._filter.text_input.text().strip().lower()
        visible_count = 0

        for host_ip, card in self._cards.items():
            show = (not text) or (text in host_ip.lower())
            card.setVisible(show)
            visible_count += show

        self._empty_lbl.setVisible(
            visible_count == 0 and not self._no_engine_lbl.isVisible()
        )
