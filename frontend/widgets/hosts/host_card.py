"""
frontend/widgets/hosts/host_card.py

Metric card for a single host with a novelty badge.
The badge reflects _classify_novelty() output directly:
  "known"     → green  KNOWN
  "new"       → amber  NEW
  "recurring" → orange RECURRING
  "loopback"  → muted  LOOPBACK
Supports in-place value updates via update() — no widget rebuilds.
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton
from PySide6.QtCore import Qt

from frontend.theme import SPACING, LAYOUT_SIZES, COMPONENT_SIZES
from frontend.widgets.shared.helpers import _lbl
from frontend.widgets.hosts.baseline_popup import BaselinePopup

# The four metric columns displayed on every card, in order.
# Each maps a display label → the snapshot key used to read the value.
_METRIC_COLS: list[tuple[str, str]] = [
    ("PKT/S",     "pkt_rate"),
    ("CONN",      "active_connections"),
    ("ANOMALY/S", "anomaly_count"),
    ("SEVERITY",  "anomaly_level"),
]

# Maps _classify_novelty() return value → (QSS objectName, badge label)
_NOVELTY_BADGE: dict[str, tuple[str, str]] = {
    "known":     ("noveltyBadgeKnown",     "KNOWN"),
    "new":       ("noveltyBadgeNew",       "NEW"),
    "recurring": ("noveltyBadgeRecurring", "RECURRING"),
    "loopback":  ("noveltyBadgeLoopback",  "LOOPBACK"),
}


class HostCard(QWidget):
    """Metric card for a single host with a novelty status badge."""

    def __init__(
        self,
        host: str,
        metrics: list[tuple[str, str]],
        baseline_data: dict,
        novelty: str = "",
        parent=None,
    ):
        super().__init__(parent)
        self.setObjectName("hostCard")
        self.setFixedHeight(LAYOUT_SIZES["card_h"])

        self._host = host
        self._baseline_data: dict = baseline_data

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            SPACING["lg"], SPACING["md"], SPACING["lg"], SPACING["md"]
        )
        layout.setSpacing(SPACING["sm"])

        # ── Row 1: hostname + novelty badge ──────────────────────────────────
        header_row = QHBoxLayout()
        header_row.setSpacing(SPACING["md"])
        header_row.addWidget(_lbl(host, "hostName"))
        header_row.addStretch()

        badge_name, badge_text = _badge_style(novelty)
        self._badge_btn = QPushButton(badge_text)
        self._badge_btn.setObjectName(badge_name)
        self._badge_btn.setFixedWidth(COMPONENT_SIZES["baseline_badge_w"])
        self._badge_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._badge_btn.clicked.connect(self._show_popup)
        self._badge_btn.setVisible(bool(badge_text))
        header_row.addWidget(self._badge_btn, 0, Qt.AlignmentFlag.AlignVCenter)

        layout.addLayout(header_row)

        # ── Row 2: metric columns ─────────────────────────────────────────────
        # Keep references to the *value* labels so update() can mutate them.
        self._value_labels: dict[str, object] = {}   # snapshot_key → QLabel

        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(SPACING["lg"])
        metrics_row.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        initial_vals: dict[str, str] = {label: val for label, val in metrics}

        for col_label, snap_key in _METRIC_COLS:
            col = QWidget()
            col.setFixedWidth(COMPONENT_SIZES["metric_col_w"])
            col_layout = QVBoxLayout(col)
            col_layout.setContentsMargins(
                SPACING["xs"], SPACING["none"], SPACING["xs"], SPACING["none"]
            )
            col_layout.setSpacing(SPACING["xs"])
            col_layout.addWidget(_lbl(col_label, "metricLabel"))
            val_lbl = _lbl(initial_vals.get(col_label, "—"), "metricValue")
            col_layout.addWidget(val_lbl)
            self._value_labels[snap_key] = val_lbl
            metrics_row.addWidget(col)

        metrics_row.addStretch()
        layout.addLayout(metrics_row)

        # ── Sparkline bar ─────────────────────────────────────────────────────
        bar = QWidget()
        bar.setObjectName("sparklineBar")
        bar.setFixedHeight(COMPONENT_SIZES["sparkline_h"])
        layout.addWidget(bar)

    def update(
        self,
        metrics: list[tuple[str, str]],
        baseline_data: dict,
        novelty: str = "",
    ) -> None:
        """Update displayed values in-place — no widget reconstruction.

        Called on every refresher tick for hosts already present in the layout.
        """
        # Update metric value labels.
        val_map: dict[str, str] = {label: val for label, val in metrics}
        for col_label, snap_key in _METRIC_COLS:
            lbl = self._value_labels.get(snap_key)
            if lbl is not None:
                lbl.setText(val_map.get(col_label, "—"))

        # Update novelty badge.
        new_name, new_text = _badge_style(novelty)
        self._badge_btn.setVisible(bool(new_text))
        if self._badge_btn.objectName() != new_name or self._badge_btn.text() != new_text:
            self._badge_btn.setObjectName(new_name)
            self._badge_btn.setText(new_text)
            # Re-polish so QSS picks up the new objectName immediately.
            self._badge_btn.style().unpolish(self._badge_btn)
            self._badge_btn.style().polish(self._badge_btn)

        # Store latest baseline payload for the popup.
        self._baseline_data = baseline_data

    def _show_popup(self) -> None:
        BaselinePopup(self._host, self._baseline_data, parent=self).exec()


def _badge_style(novelty: str) -> tuple[str, str]:
    """Map a _classify_novelty() value to (QSS objectName, badge label).

    Returns ("", "") for any unrecognised value — caller hides the button.
    """
    return _NOVELTY_BADGE.get(novelty.lower() if novelty else "", ("", ""))
