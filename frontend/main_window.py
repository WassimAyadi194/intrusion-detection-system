"""Main application window.

Provides a collapsible left-column navigation sidebar and a content stack
that hosts all pages (Dashboard, Settings).
"""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QStackedWidget, QPushButton, QSizePolicy,
)
from PySide6.QtCore import Qt

from frontend.theme import SPACING, LAYOUT_SIZES, FONT, COLORS, COMPONENT_SIZES
from frontend.pages.dashboard import DashboardPage
from frontend.pages.settings_page import SettingsPage


class MainWindow(QMainWindow):

    def __init__(self, alert_queue=None, log_queue=None, engine=None):
        super().__init__()
        self.setWindowTitle("Intrusion Detection System")
        self.setMinimumSize(1024, 640)
        self.resize(1280, 760)

        # Central widget
        central = QWidget()
        central.setObjectName("centralWidget")
        self.setCentralWidget(central)

        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── Left sidebar ──────────────────────────────────────────────────────
        self._sidebar_expanded = True
        self._left_col = QWidget()
        self._left_col.setObjectName("leftColumn")

        sidebar_layout = QVBoxLayout(self._left_col)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        # Brand + collapse toggle in the same header bar
        brand_bar = QWidget()
        brand_bar.setObjectName("brandBar")
        brand_bar.setFixedHeight(LAYOUT_SIZES["brand_label_h"])
        bb_row = QHBoxLayout(brand_bar)
        bb_row.setContentsMargins(0, 0, 0, 0)
        bb_row.setSpacing(0)

        self._brand_text = "INTRUSION DETECTION SYSTEM"
        self._brand_btn = QPushButton(self._brand_text)
        self._brand_btn.setObjectName("brandLabel")
        self._brand_btn.setFixedHeight(LAYOUT_SIZES["brand_label_h"])
        self._brand_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self._toggle_sidebar_btn = QPushButton("«")
        self._toggle_sidebar_btn.setObjectName("toggleButton")
        self._toggle_sidebar_btn.setFixedSize(
            LAYOUT_SIZES["sidebar_w_collapsed"],
            LAYOUT_SIZES["brand_label_h"],
        )
        self._toggle_sidebar_btn.clicked.connect(self._toggle_sidebar)

        bb_row.addWidget(self._brand_btn, stretch=1)
        bb_row.addWidget(self._toggle_sidebar_btn)
        sidebar_layout.addWidget(brand_bar)

        self._expanded_width = LAYOUT_SIZES["sidebar_w_expanded"]
        self._left_col.setFixedWidth(self._expanded_width)

        # Nav buttons
        self._icon_dashboard = "❖"
        self._text_dashboard = "Dashboard"
        self._nav_dashboard = QPushButton(f"{self._icon_dashboard}   {self._text_dashboard}")
        self._nav_dashboard.setObjectName("navButton")
        self._nav_dashboard.setCheckable(True)
        self._nav_dashboard.setChecked(True)
        self._nav_dashboard.setFixedHeight(LAYOUT_SIZES["nav_button_h"])
        self._nav_dashboard.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )

        self._icon_settings = "⚙"
        self._text_settings = "Settings"
        self._nav_settings = QPushButton(f"{self._icon_settings}    {self._text_settings}")
        self._nav_settings.setObjectName("navButton")
        self._nav_settings.setCheckable(True)
        self._nav_settings.setFixedHeight(LAYOUT_SIZES["nav_button_h"])
        self._nav_settings.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )

        sidebar_layout.addWidget(self._nav_dashboard)
        sidebar_layout.addWidget(self._nav_settings)
        sidebar_layout.addStretch(1)

        root_layout.addWidget(self._left_col)

        # ── Content stack ─────────────────────────────────────────────────────
        self.stack = QStackedWidget()
        self.stack.setObjectName("contentStack")

        self._dashboard_page = DashboardPage(
            alert_queue=alert_queue,
            log_queue=log_queue,
            engine=engine,
        )
        self._settings_page = SettingsPage(engine=engine)

        # Forward engine lifecycle events from the dashboard to the settings page
        # so that Apply always targets the current live instance.
        self._dashboard_page.engine_changed.connect(self._settings_page.set_engine)

        self.stack.addWidget(self._dashboard_page)   # index 0
        self.stack.addWidget(self._settings_page)    # index 1

        root_layout.addWidget(self.stack, stretch=1)

        # ── Nav wiring ────────────────────────────────────────────────────────
        self._nav_dashboard.clicked.connect(lambda: self._switch_page(0))
        self._nav_settings.clicked.connect(lambda: self._switch_page(1))

        self.stack.setCurrentIndex(0)

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def _switch_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        self._nav_dashboard.setChecked(index == 0)
        self._nav_settings.setChecked(index == 1)

    # ------------------------------------------------------------------
    # Sidebar collapse / expand
    # ------------------------------------------------------------------

    def _toggle_sidebar(self) -> None:
        self._sidebar_expanded = not self._sidebar_expanded
        if self._sidebar_expanded:
            self._left_col.setFixedWidth(self._expanded_width)
            self._toggle_sidebar_btn.setText("«")
            self._brand_btn.show()
            self._brand_btn.setText(self._brand_text)
            self._nav_dashboard.setText(f"{self._icon_dashboard}   {self._text_dashboard}")
            self._nav_settings.setText(f"{self._icon_settings}    {self._text_settings}")
        else:
            self._left_col.setFixedWidth(LAYOUT_SIZES["sidebar_w_collapsed"])
            self._toggle_sidebar_btn.setText("»")
            self._brand_btn.hide()
            self._nav_dashboard.setText(self._icon_dashboard)
            self._nav_settings.setText(self._icon_settings)