"""
frontend/widgets/alerts/alert_entry.py

Single row widget displayed inside the Alert Feed.
"""

from PySide6.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QSizePolicy
from PySide6.QtCore import Qt

from frontend.theme import SPACING, LAYOUT_SIZES, COMPONENT_SIZES
from frontend.widgets.shared.helpers import _lbl


def _badge_cell(severity: str) -> QWidget:
    """
    Return a plain QWidget of fixed size (badge_col_w × badge_h) containing
    a centred severity QLabel.

    The outer QWidget has NO objectName and therefore NO QSS geometry rules
    can target it — its setFixedSize() call is absolute and permanent.
    The inner QLabel carries the styled objectName so colour/border QSS rules
    apply normally, but can no longer influence the column width.
    """
    # Determine the visual badge width (CRITICAL is wider than the others).
    badge_visual_w = (
        COMPONENT_SIZES["badge_w_lg"] if severity == "CRITICAL"
        else COMPONENT_SIZES["badge_w"]
    )

    # Outer container — geometry owner, invisible to QSS.
    cell = QWidget()
    # Fixed at the column reservation width so every row's badge slot is
    # identical regardless of severity text length.
    cell.setFixedSize(COMPONENT_SIZES["badge_col_w"], COMPONENT_SIZES["badge_h"])
    cell.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

    inner = QHBoxLayout(cell)
    inner.setContentsMargins(SPACING["none"], SPACING["none"],
                             SPACING["none"], SPACING["none"])
    inner.setSpacing(SPACING["none"])

    sev_name = f"severityBadge{severity.capitalize()}"
    badge = _lbl(severity, sev_name, Qt.AlignmentFlag.AlignCenter)
    # The label fills the visual badge width; the cell owns the column width.
    badge.setFixedSize(badge_visual_w, COMPONENT_SIZES["badge_h"])
    badge.setAlignment(Qt.AlignmentFlag.AlignCenter)

    inner.addWidget(badge, 0, Qt.AlignmentFlag.AlignCenter)
    return cell


class AlertEntry(QWidget):
    """One row in the alert feed."""

    def __init__(self, timestamp: str, severity: str, host: str,
                 description: str, parent=None):
        super().__init__(parent)
        self.setObjectName("alertEntry")

        # Minimum row height — expands naturally when description wraps.
        self.setMinimumHeight(LAYOUT_SIZES["row_h"])
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        # Expose for filtering
        self._severity = severity
        self._host = host

        row = QHBoxLayout(self)
        row.setContentsMargins(
            SPACING["lg"], SPACING["sm"], SPACING["lg"], SPACING["sm"]
        )
        row.setSpacing(SPACING["lg"])

        # ── Badge column (fixed-width container, immune to QSS resizing) ──
        row.addWidget(_badge_cell(severity), 0, Qt.AlignmentFlag.AlignTop)

        # ── Timestamp ─────────────────────────────────────────────────────
        ts = _lbl(timestamp, "alertTimestamp")
        ts.setFixedWidth(COMPONENT_SIZES["timestamp_col_w"])
        ts.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        row.addWidget(ts, 0, Qt.AlignmentFlag.AlignTop)

        # ── Host / IP ─────────────────────────────────────────────────────
        h = _lbl(host, "alertHost")
        h.setFixedWidth(COMPONENT_SIZES["host_col_w"])
        h.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        row.addWidget(h, 0, Qt.AlignmentFlag.AlignTop)

        # ── Description (word-wrapping, expands row height) ───────────────
        desc = _lbl(description, "alertDesc")
        desc.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        desc.setWordWrap(True)
        desc.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        row.addWidget(desc, 1, Qt.AlignmentFlag.AlignTop)