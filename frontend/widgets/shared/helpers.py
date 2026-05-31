"""
frontend/widgets/shared/helpers.py

Shared primitive factory functions used across all dashboard widgets.
"""

from PySide6.QtWidgets import QWidget, QLabel, QHBoxLayout, QScrollArea, QFrame, QSizePolicy
from PySide6.QtCore import Qt

from frontend.theme import SPACING, LAYOUT_SIZES


def _lbl(text: str, name: str, align=Qt.AlignmentFlag.AlignLeft, parent=None) -> QLabel:
    lbl = QLabel(text, parent)
    lbl.setObjectName(name)
    lbl.setAlignment(align)
    return lbl


def _panel_header(title: str, subtitle: str = "") -> QWidget:
    """Reusable dark header bar used atop each panel."""
    header = QWidget()
    header.setObjectName("panelHeader")
    header.setFixedHeight(LAYOUT_SIZES["panel_header_h"])
    row = QHBoxLayout(header)
    row.setContentsMargins(
        SPACING["lg"], SPACING["md"], SPACING["lg"], SPACING["md"]
    )
    row.setSpacing(SPACING["md"])
    row.addWidget(_lbl(title, "panelTitle"))
    row.addStretch()
    if subtitle:
        row.addWidget(_lbl(subtitle, "panelSubtitle"))
    return header


def _scrollable(inner: QWidget) -> QScrollArea:
    """Wrap *inner* in a frameless, horizontally-locked scroll area.

    The scroll area is given an Expanding/Expanding size policy so that it
    fills all available space in its parent layout. Without this, Qt defaults
    to a Preferred/Preferred policy that lets the viewport be squeezed down to
    only a few visible rows even when more space is available.
    """
    scroll = QScrollArea()
    scroll.setObjectName("transparentScroll")
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    scroll.setWidget(inner)
    # Ensure the scroll area always expands to consume all available space
    # from its parent layout — prevents the "only N rows visible" squeeze bug.
    scroll.setSizePolicy(
        QSizePolicy.Policy.Expanding,
        QSizePolicy.Policy.Expanding,
    )
    return scroll