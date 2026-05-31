"""
frontend/widgets/bottom_bar.py

Heartbeat indicator + stall warning bar.
"""

from PySide6.QtWidgets import QWidget, QHBoxLayout
from PySide6.QtCore import Qt

from frontend.theme import SPACING, LAYOUT_SIZES
from frontend.widgets.shared.helpers import _lbl


class BottomBar(QWidget):
    """Heartbeat indicator + stall warning."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("dashBottomBar")
        self.setFixedHeight(LAYOUT_SIZES["bottom_bar_h"])

        row = QHBoxLayout(self)
        row.setContentsMargins(
            SPACING["xl"], SPACING["xs"], SPACING["xl"], SPACING["xs"]
        )
        row.setSpacing(SPACING["sm"])

        row.addWidget(_lbl("●", "heartbeatPulse"))

        self._tick_label = _lbl("HEARTBEAT  ·  LAST TICK: —", "heartbeatLabel")
        row.addWidget(self._tick_label)

        row.addStretch()

        self._stall_badge = _lbl("⚠  STALL", "noStallBadge", Qt.AlignmentFlag.AlignCenter)
        row.addWidget(self._stall_badge)

    def update_status(self, last_tick: str, stall: bool) -> None:
        """Update heartbeat tick time and stall warning badge.

        Args:
            last_tick: Formatted timestamp string for the last heartbeat tick.
            stall:     True if a stall condition is active, False otherwise.
        """
        self._tick_label.setText(f"HEARTBEAT  ·  LAST TICK: {last_tick}")

        if stall:
            self._stall_badge.setText("⚠  STALL DETECTED")
            self._stall_badge.setObjectName("stallBadge")
        else:
            self._stall_badge.setText("✔ NO STALL")
            self._stall_badge.setObjectName("noStallBadge")

        # Re-polish so QSS rules tied to objectName are re-evaluated.
        self._stall_badge.style().unpolish(self._stall_badge)
        self._stall_badge.style().polish(self._stall_badge)