"""
frontend/pages/settings_page.py

Full-page wrapper around SettingsPanel.
The page header mirrors the dashboard page pattern.
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from PySide6.QtCore import Qt

from frontend.theme import SPACING, LAYOUT_SIZES
from frontend.widgets.shared.helpers import _lbl
from frontend.widgets.settings.settings_panel import SettingsPanel


class SettingsPage(QWidget):

    def __init__(self, engine=None, parent=None):
        super().__init__(parent)
        self.setObjectName("settingsPage")

        root = QVBoxLayout(self)
        root.setContentsMargins(
            SPACING["none"], SPACING["none"], SPACING["none"], SPACING["none"]
        )
        root.setSpacing(SPACING["xs"])

        root.addWidget(self._build_page_header())

        self._panel = SettingsPanel(engine=engine, parent=self)
        root.addWidget(self._panel, stretch=1)

    # ------------------------------------------------------------------
    # Page header
    # ------------------------------------------------------------------

    def _build_page_header(self) -> QWidget:
        header = QWidget()
        header.setObjectName("pageHeader")
        header.setFixedHeight(LAYOUT_SIZES["page_header_h"])
        row = QHBoxLayout(header)
        row.setContentsMargins(
            SPACING["xxl"], SPACING["xxl"], SPACING["xxl"], SPACING["lg"]
        )
        row.addWidget(_lbl("SETTINGS", "pageHeaderTitle"))
        row.addStretch()
        return header

    # ------------------------------------------------------------------
    # Engine wiring — forwarded to the inner SettingsPanel
    # ------------------------------------------------------------------

    def set_engine(self, engine) -> None:
        """Call when the engine starts or stops so Apply always targets the live instance."""
        self._panel.set_engine(engine)
