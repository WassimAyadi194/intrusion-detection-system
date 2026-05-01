"""Main application window."""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QStackedWidget
)

from frontend.pages.dashboard import DashboardPage

class MainWindow(QMainWindow):

    def __init__(self, alert_queue=None, log_queue=None, engine=None):
        super().__init__()
        self.setWindowTitle("Antigravity IDS")
        self.setMinimumSize(1024, 640)
        self.resize(1280, 760)

        # Central widget
        central = QWidget()
        central.setObjectName("centralWidget")
        self.setCentralWidget(central)

        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Full-width content stack
        self.stack = QStackedWidget()
        self.stack.setObjectName("contentStack")

        self._pages = [DashboardPage(alert_queue=alert_queue, log_queue=log_queue, engine=engine)]
        for page in self._pages:
            self.stack.addWidget(page)

        root_layout.addWidget(self.stack)

        self.stack.setCurrentIndex(0)