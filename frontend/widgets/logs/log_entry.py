"""
frontend/widgets/logs/log_entry.py

Single row widget displayed inside the Logs Panel.
"""

from PySide6.QtWidgets import QWidget, QHBoxLayout
from PySide6.QtCore import Qt

from frontend.theme import SPACING, LAYOUT_SIZES, COMPONENT_SIZES
from frontend.widgets.shared.helpers import _lbl


class LogEntry(QWidget):
    """One row in the logs panel."""

    def __init__(self, timestamp: str, level: str, message: str, parent=None):
        super().__init__(parent)
        self.setObjectName("logEntry")
        self.setFixedHeight(LAYOUT_SIZES["row_h"])
        self._message = message  # exposed for text filtering

        row = QHBoxLayout(self)
        row.setContentsMargins(
            SPACING["lg"], SPACING["sm"], SPACING["lg"], SPACING["sm"]
        )
        row.setSpacing(SPACING["lg"])

        ts = _lbl(timestamp, "logTimestamp", Qt.AlignmentFlag.AlignVCenter)
        ts.setFixedWidth(COMPONENT_SIZES["timestamp_col_w"])
        row.addWidget(ts, 0, Qt.AlignmentFlag.AlignVCenter)

        _LEVEL_NORM = {
            "WARN":     "WARNING",
            "ERR":      "ERROR",
        }
        normalized = _LEVEL_NORM.get(level.upper(), level.upper())
        lvl_name = f"logLevel{normalized.capitalize()}"
        lvl = _lbl(level, lvl_name, Qt.AlignmentFlag.AlignCenter)
        lvl.setFixedWidth(COMPONENT_SIZES["badge_w"])
        row.addWidget(lvl, 0, Qt.AlignmentFlag.AlignVCenter)

        row.addWidget(
            _lbl(message, "logText", Qt.AlignmentFlag.AlignVCenter),
            1, Qt.AlignmentFlag.AlignVCenter,
        )
