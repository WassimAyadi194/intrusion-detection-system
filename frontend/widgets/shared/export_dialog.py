from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QCheckBox, QLabel
)
from PySide6.QtCore import Qt

from frontend.theme import SPACING, LAYOUT_SIZES
from frontend.widgets.shared.helpers import _lbl

class ExportDialog(QDialog):
    """A minimalistic dialog to select tables to export to CSV."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export to CSV")
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowCloseButtonHint)
        self.setMinimumWidth(300)
        



        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACING["lg"], SPACING["lg"], SPACING["lg"], SPACING["lg"])
        layout.setSpacing(SPACING["md"])

        title = _lbl("Select tables to export:", "panelTitle")
        layout.addWidget(title)

        self.cb_alerts = QCheckBox("Alerts")
        self.cb_alerts.setChecked(True)
        self.cb_logs = QCheckBox("Logs")
        self.cb_logs.setChecked(True)
        self.cb_baseline = QCheckBox("Baseline")
        self.cb_baseline.setChecked(True)

        layout.addWidget(self.cb_alerts)
        layout.addWidget(self.cb_logs)
        layout.addWidget(self.cb_baseline)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(SPACING["sm"])
        btn_layout.addStretch(1)

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setObjectName("secondaryBtn")
        self.btn_cancel.clicked.connect(self.reject)
        
        self.btn_export = QPushButton("Export")
        self.btn_export.setObjectName("primaryBtn")
        self.btn_export.clicked.connect(self.accept)

        btn_layout.addWidget(self.btn_cancel)
        btn_layout.addWidget(self.btn_export)

        layout.addSpacing(SPACING["md"])
        layout.addLayout(btn_layout)

    def get_selected_tables(self) -> list[str]:
        tables = []
        if self.cb_alerts.isChecked():
            tables.append("alerts")
        if self.cb_logs.isChecked():
            tables.append("logs")
        if self.cb_baseline.isChecked():
            tables.append("baseline")
        return tables
