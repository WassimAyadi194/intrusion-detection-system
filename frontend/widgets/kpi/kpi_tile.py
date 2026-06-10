"""
frontend/widgets/kpi/kpi_tile.py

Single KPI card: title + big value + optional unit.
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QSizePolicy, QLabel
from PySide6.QtCore import Qt

from frontend.theme import SPACING, LAYOUT_SIZES
from frontend.widgets.shared.helpers import _lbl


class KpiTile(QWidget):
    """Single KPI card: title + big value + optional unit."""

    def __init__(self, title: str, value: str, unit: str = "",
                 value_name: str = "kpiValue", parent=None):
        super().__init__(parent)
        self.setObjectName("kpiTile")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(LAYOUT_SIZES["kpi_tile_h"])

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            SPACING["xl"], SPACING["lg"], SPACING["xl"], SPACING["lg"]
        )
        layout.setSpacing(SPACING["sm"])

        layout.addWidget(_lbl(title.upper(), "kpiTitle"))

        value_row = QHBoxLayout()
        value_row.setSpacing(SPACING["md"])

        self._value_label: QLabel = _lbl(value, value_name)
        value_row.addWidget(self._value_label)

        if unit:
            value_row.addWidget(_lbl(unit, "kpiUnit", Qt.AlignmentFlag.AlignBottom))
        value_row.addStretch()
        layout.addLayout(value_row)

    # ------------------------------------------------------------------
    # Public update API
    # ------------------------------------------------------------------

    def set_value(self, value: str) -> None:
        """Update the displayed value without rebuilding the widget."""
        self._value_label.setText(value)

    def set_color_class(self, color_class: str) -> None:
        """Dynamically switch the CSS color class of the big value."""
        self._value_label.setObjectName(color_class)
        self._value_label.style().unpolish(self._value_label)
        self._value_label.style().polish(self._value_label)