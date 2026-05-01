"""
frontend/widgets/hosts/baseline_popup.py

Modal dialog showing stored baseline values for a host.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFrame, QDialogButtonBox,
)
from PySide6.QtCore import Qt

from frontend.theme import SPACING, LAYOUT_SIZES
from frontend.widgets.shared.helpers import _lbl


class BaselinePopup(QDialog):
    """Modal dialog showing stored baseline values for a host."""

    def __init__(self, host: str, baseline: dict[str, str], parent=None):
        super().__init__(parent)
        self.setObjectName("baselinePopup")
        self.setWindowTitle(f"Baseline — {host}")
        self.setMinimumWidth(LAYOUT_SIZES["baseline_popup_w"])

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            SPACING["xl"], SPACING["xl"], SPACING["xl"], SPACING["xl"]
        )
        layout.setSpacing(SPACING["md"])

        layout.addWidget(_lbl(f"HOST:  {host}", "popupHostLabel"))

        sep = QFrame()
        sep.setObjectName("popupSeparator")
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)

        if baseline:
            for key, val in baseline.items():
                # baseline_reader returns raw sqlite3 types (float, int, str).
                # QLabel only accepts str; passing a float raises TypeError inside
                # the PySide6 C++ binding which PySide6 swallows silently in slots
                # — the dialog would never appear.  Format floats to 4 d.p. so
                # values like avg_syn=4.3120001 display cleanly.
                if isinstance(val, float):
                    display_val = f"{val:.4f}"
                else:
                    display_val = str(val) if val is not None else "—"
                kv = QHBoxLayout()
                kv.setSpacing(SPACING["xl"])
                kv.addWidget(_lbl(str(key), "popupKey"))
                kv.addStretch()
                kv.addWidget(_lbl(display_val, "popupValue", Qt.AlignmentFlag.AlignRight))
                layout.addLayout(kv)
        else:
            layout.addWidget(
                _lbl("No baseline recorded for this host.", "popupEmpty",
                     Qt.AlignmentFlag.AlignCenter)
            )

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)
