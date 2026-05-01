"""
frontend/widgets/shared/filter_bar.py

Reusable filter row widget: optional severity combo + free-text search input.
"""

from PySide6.QtWidgets import QWidget, QHBoxLayout, QComboBox, QLineEdit

from frontend.theme import SPACING


class FilterBar(QWidget):
    """Reusable filter row: optional severity combo + free-text search input."""

    def __init__(self, placeholder: str = "Filter…",
                 severities: list[str] | None = None, parent=None):
        super().__init__(parent)
        self.setObjectName("filterBar")

        row = QHBoxLayout(self)
        row.setContentsMargins(
            SPACING["lg"], SPACING["sm"], SPACING["lg"], SPACING["sm"]
        )
        row.setSpacing(SPACING["md"])

        self._combo: QComboBox | None = None
        if severities:
            self._combo = QComboBox()
            self._combo.setObjectName("filterCombo")
            for s in severities:
                self._combo.addItem(s)
            row.addWidget(self._combo)

        self._input = QLineEdit()
        self._input.setObjectName("filterInput")
        self._input.setPlaceholderText(placeholder)
        row.addWidget(self._input, stretch=1)

    @property
    def combo(self) -> QComboBox | None:
        return self._combo

    @property
    def text_input(self) -> QLineEdit:
        return self._input
