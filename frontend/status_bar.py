"""Static status bar displayed beneath the sidebar."""

from PySide6.QtWidgets import QWidget, QHBoxLayout, QLabel
from PySide6.QtCore import Qt

from frontend.theme import LAYOUT_SIZES, SPACING


class StatusBar(QWidget):
    """
    Fixed-height bar pinned to the bottom-left of the layout.
    Displays static placeholder system state text.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("StatusBar")
        self.setFixedHeight(LAYOUT_SIZES["status_bar_h"])

        layout = QHBoxLayout(self)
        layout.setContentsMargins(
            SPACING["lg"], SPACING["none"], SPACING["lg"], SPACING["none"]
        )
        layout.setSpacing(SPACING["none"])

        # Static system label
        self._status_label = QLabel("●  IDS ACTIVE")
        self._status_label.setObjectName("statusLabel")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)

        layout.addWidget(self._status_label)
        layout.addStretch()