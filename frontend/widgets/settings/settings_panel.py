"""
frontend/widgets/settings/settings_panel.py

A self-contained panel that exposes all tunable detector parameters as
labelled spin-box inputs.  Clicking "Apply" pushes new values onto the live
detector instances and persists them to ids_settings.json so that they survive
a Stop/Start cycle.

Layout
------
Three collapsible groups (one per detector), each containing labelled rows.
A sticky "Apply" / "Reset to defaults" button bar lives at the bottom.

Thread-safety
-------------
All writes to detector instance attributes happen on the Qt main thread
(triggered by the Apply button click).  Single-assignment writes to float/int
attrs are atomic under CPython's GIL.  Dict / set fields are replaced
atomically (whole-object swap) to avoid partial-read races.
"""

import config
from config import save_settings

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QDoubleSpinBox, QSpinBox, QScrollArea, QFrame, QSizePolicy, QAbstractSpinBox
)
from PySide6.QtCore import Qt, QTimer

from frontend.theme import COLORS, SPACING, FONT, LAYOUT_SIZES, COMPONENT_SIZES
from frontend.widgets.shared.helpers import _lbl


# ---------------------------------------------------------------------------
# Helper: build one labelled row with a spin-box
# ---------------------------------------------------------------------------

def _spin_row(
    label_text: str,
    tooltip: str,
    widget: QSpinBox | QDoubleSpinBox,
    parent_layout: QVBoxLayout,
) -> None:
    """Append a (label | spacer | spinbox) row to *parent_layout*."""
    row = QHBoxLayout()
    row.setSpacing(SPACING["md"])
    row.setContentsMargins(
        SPACING["lg"], SPACING["xs"], SPACING["lg"], SPACING["xs"]
    )

    lbl = QLabel(label_text)
    lbl.setObjectName("settingLabel")
    lbl.setToolTip(tooltip)
    lbl.setWordWrap(True)
    lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

    widget.setObjectName("settingSpinBox")
    widget.setToolTip(tooltip)
    widget.setFixedWidth(90)

    row.addWidget(lbl)
    row.addWidget(widget)
    parent_layout.addLayout(row)


def _section_header(title: str) -> QLabel:
    lbl = QLabel(title)
    lbl.setObjectName("settingSectionHeader")
    return lbl


def _separator() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setObjectName("settingSeparator")
    return line


class NoScrollDoubleSpinBox(QDoubleSpinBox):
    def wheelEvent(self, event):
        event.ignore()

class NoScrollSpinBox(QSpinBox):
    def wheelEvent(self, event):
        event.ignore()

def _make_float_spin(
    value: float, lo: float, hi: float, step: float, decimals: int = 2
) -> QDoubleSpinBox:
    sb = NoScrollDoubleSpinBox()
    sb.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    sb.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
    sb.setRange(lo, hi)
    sb.setSingleStep(step)
    sb.setDecimals(decimals)
    sb.setValue(value)
    return sb


def _make_int_spin(value: int, lo: int, hi: int, step: int = 1) -> QSpinBox:
    sb = NoScrollSpinBox()
    sb.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    sb.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
    sb.setRange(lo, hi)
    sb.setSingleStep(step)
    sb.setValue(value)
    return sb


# ---------------------------------------------------------------------------
# Main widget
# ---------------------------------------------------------------------------

class SettingsPanel(QWidget):
    """
    Renders all tunable IDS parameters and wires them to the live engine.

    Parameters
    ----------
    engine : DetectionEngine | None
        The live engine instance.  Can be None if the IDS is stopped; Apply
        will still persist to JSON so the next Start picks up the new values.
    parent : QWidget | None
    """

    def __init__(self, engine=None, parent=None):
        super().__init__(parent)
        self.setObjectName("settingsPanel")
        self._engine = engine

        root = QVBoxLayout(self)
        root.setContentsMargins(
            SPACING["none"], SPACING["none"], SPACING["none"], SPACING["none"]
        )
        root.setSpacing(SPACING["none"])

        # Scrollable body
        body_inner = QWidget()
        body_inner.setObjectName("settingsBody")
        body_layout = QVBoxLayout(body_inner)
        body_layout.setContentsMargins(
            SPACING["xl"], SPACING["lg"], SPACING["xl"], SPACING["lg"]
        )
        body_layout.setSpacing(SPACING["sm"])

        self._build_packet_section(body_layout)
        body_layout.addWidget(_separator())
        self._build_port_scan_section(body_layout)
        body_layout.addWidget(_separator())
        self._build_anomaly_section(body_layout)
        body_layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setObjectName("transparentScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(body_inner)
        scroll.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        root.addWidget(scroll, stretch=1)

        root.addWidget(self._build_button_bar())
        
        self._wire_signals()
        self._check_changes()

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------

    def _build_packet_section(self, layout: QVBoxLayout) -> None:
        layout.addWidget(_section_header("Packet Flood Detector"))

        cfg = config
        self._pkt_k        = _make_float_spin(cfg.PACKET_K, 0.1, 20.0, 0.1)
        self._pkt_min_thr  = _make_int_spin(cfg.PACKET_MIN_GLOBAL_THRESHOLD, 1, 100_000, 100)
        self._pkt_window   = _make_int_spin(cfg.PACKET_WINDOW, 1, 300, 1)
        self._pkt_pen_nov  = _make_float_spin(
            cfg.PACKET_SENSITIVITY_PENALTIES.get("novelty_new", 0.8), 0.1, 1.0, 0.05
        )
        self._pkt_pen_fail = _make_float_spin(
            cfg.PACKET_SENSITIVITY_PENALTIES.get("high_failure_ratio", 0.8), 0.1, 1.0, 0.05
        )
        self._pkt_fail_thr = _make_float_spin(
            cfg.PACKET_HIGH_FAILURE_RATIO_THRESHOLD, 0.1, 1.0, 0.05
        )

        _spin_row("σ multiplier (K)",
                  "Threshold = mean + K × std.  Higher → less sensitive.",
                  self._pkt_k, layout)
        _spin_row("Min global threshold (packets)",
                  "Hard lower bound for the computed flood threshold.",
                  self._pkt_min_thr, layout)
        _spin_row("Detection window (s)",
                  "Rolling window over which per-source packet counts accumulate.",
                  self._pkt_window, layout)
        _spin_row("Novelty penalty multiplier",
                  "Applied when a source has no baseline entry.  < 1.0 → stricter.",
                  self._pkt_pen_nov, layout)
        _spin_row("High-failure-rate penalty multiplier",
                  "Applied when RST/timeout ratio exceeds the threshold below.  < 1.0 → stricter.",
                  self._pkt_pen_fail, layout)
        _spin_row("High-failure-rate threshold",
                  "RST/timeout ratio above which the penalty is applied.",
                  self._pkt_fail_thr, layout)

    def _build_port_scan_section(self, layout: QVBoxLayout) -> None:
        layout.addWidget(_section_header("Port Scan Detector"))

        cfg = config
        self._ps_k         = _make_float_spin(cfg.PORT_SCAN_K, 0.1, 20.0, 0.1)
        self._ps_min_port  = _make_int_spin(cfg.PORT_SCAN_MIN_PORT_SCAN_LIMIT, 1, 1000, 1)
        self._ps_min_host  = _make_int_spin(cfg.PORT_SCAN_MIN_HOST_SCAN_LIMIT, 1, 1000, 1)
        self._ps_pen_nov   = _make_float_spin(
            cfg.PORT_SCAN_SENSITIVITY_PENALTIES.get("novelty_new", 0.8), 0.1, 1.0, 0.05
        )
        self._ps_pen_fail  = _make_float_spin(
            cfg.PORT_SCAN_SENSITIVITY_PENALTIES.get("high_failure_ratio", 0.8), 0.1, 1.0, 0.05
        )
        self._ps_fail_thr  = _make_float_spin(
            cfg.PORT_SCAN_HIGH_FAILURE_RATIO_THRESHOLD, 0.1, 1.0, 0.05
        )
        self._ps_static_ports = _make_int_spin(
            next(iter(cfg.PORT_SCAN_STATIC_THRESHOLD_PORTS), 443), 1, 65535, 1
        )

        _spin_row("σ multiplier (K)",
                  "Threshold = mean + K × std.  Higher → less sensitive.",
                  self._ps_k, layout)
        _spin_row("Min port-scan limit (unique ports)",
                  "Hard floor for the vertical (per-destination) threshold.",
                  self._ps_min_port, layout)
        _spin_row("Min host-scan limit (unique hosts)",
                  "Hard floor for the horizontal (per-port) threshold.",
                  self._ps_min_host, layout)
        _spin_row("Novelty penalty multiplier",
                  "Applied when a source has no baseline entry.  < 1.0 → stricter.",
                  self._ps_pen_nov, layout)
        _spin_row("High-failure-rate penalty multiplier",
                  "Applied when RST/timeout ratio exceeds the threshold below.  < 1.0 → stricter.",
                  self._ps_pen_fail, layout)
        _spin_row("High-failure-rate threshold",
                  "RST/timeout ratio above which the penalty is applied.",
                  self._ps_fail_thr, layout)
        _spin_row("Static-threshold port (penalty suppressed)",
                  "Traffic to this port uses baseline mean+std but ignores sensitivity penalties.",
                  self._ps_static_ports, layout)

    def _build_anomaly_section(self, layout: QVBoxLayout) -> None:
        layout.addWidget(_section_header("Anomaly Detector"))

        cfg = config
        self._an_std_floor  = _make_float_spin(cfg.ANOMALY_STD_FLOOR, 0.01, 100.0, 0.1)
        self._an_min_samp   = _make_int_spin(cfg.ANOMALY_MIN_BASELINE_SAMPLES, 1, 10_000, 1)
        self._an_del_syn    = _make_float_spin(
            cfg.ANOMALY_MIN_DELTAS.get("syn_count", 20.0), 0.0, 10_000.0, 1.0, 1
        )
        self._an_del_ports  = _make_float_spin(
            cfg.ANOMALY_MIN_DELTAS.get("unique_ports", 10.0), 0.0, 10_000.0, 1.0, 1
        )
        self._an_del_dests  = _make_float_spin(
            cfg.ANOMALY_MIN_DELTAS.get("unique_destinations", 10.0), 0.0, 10_000.0, 1.0, 1
        )
        self._an_del_pkts   = _make_float_spin(
            cfg.ANOMALY_MIN_DELTAS.get("packet_count", 1000.0), 0.0, 1_000_000.0, 10.0, 0
        )

        _spin_row("Std floor",
                  "Minimum effective std before Z-score division.  Prevents division by near-zero.",
                  self._an_std_floor, layout)
        _spin_row("Min baseline samples",
                  "Baselines with fewer samples than this are ignored (avoids false positives on sparse data).",
                  self._an_min_samp, layout)
        _spin_row("Min delta — SYN count",
                  "Absolute change required before a SYN anomaly alert can fire.",
                  self._an_del_syn, layout)
        _spin_row("Min delta — unique ports",
                  "Absolute change required before a unique-ports anomaly alert can fire.",
                  self._an_del_ports, layout)
        _spin_row("Min delta — unique destinations",
                  "Absolute change required before a unique-destinations anomaly alert can fire.",
                  self._an_del_dests, layout)
        _spin_row("Min delta — packet count",
                  "Absolute change required before a packet-count anomaly alert can fire.",
                  self._an_del_pkts, layout)

    # ------------------------------------------------------------------
    # Button bar
    # ------------------------------------------------------------------

    def _build_button_bar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("settingsButtonBar")
        row = QHBoxLayout(bar)
        row.setContentsMargins(
            SPACING["xl"], SPACING["md"], SPACING["xl"], SPACING["md"]
        )
        row.setSpacing(SPACING["md"])

        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.setObjectName("settingsResetBtn")
        reset_btn.clicked.connect(self._reset_defaults)

        self._success_lbl = QLabel("✓ Settings Applied")
        self._success_lbl.setObjectName("settingSuccessLabel")
        self._success_lbl.setStyleSheet(f"color: {COLORS['accent_green']}; font-weight: 700; font-size: {FONT['sm_body']}px;")
        self._success_lbl.hide()

        self._apply_btn = QPushButton("Apply")
        self._apply_btn.setObjectName("settingsApplyBtn")
        self._apply_btn.clicked.connect(self._apply)
        self._apply_btn.setEnabled(False)

        row.addStretch(1)
        row.addWidget(self._success_lbl)
        row.addWidget(reset_btn)
        row.addWidget(self._apply_btn)
        return bar

    # ------------------------------------------------------------------
    # State tracking
    # ------------------------------------------------------------------

    def _wire_signals(self) -> None:
        spins = [
            self._pkt_k, self._pkt_min_thr, self._pkt_window,
            self._pkt_pen_nov, self._pkt_pen_fail, self._pkt_fail_thr,
            self._ps_k, self._ps_min_port, self._ps_min_host,
            self._ps_pen_nov, self._ps_pen_fail, self._ps_fail_thr,
            self._ps_static_ports,
            self._an_std_floor, self._an_min_samp, self._an_del_syn,
            self._an_del_ports, self._an_del_dests, self._an_del_pkts,
        ]
        for spin in spins:
            spin.valueChanged.connect(lambda _: self._check_changes())

    def _check_changes(self) -> None:
        changed = False
        
        # Helper to check float equality due to double spinbox quirks
        def differs(a, b): return abs(a - b) > 1e-5

        cfg = config
        
        if differs(self._pkt_k.value(), cfg.PACKET_K): changed = True
        if self._pkt_min_thr.value() != cfg.PACKET_MIN_GLOBAL_THRESHOLD: changed = True
        if self._pkt_window.value() != cfg.PACKET_WINDOW: changed = True
        if differs(self._pkt_pen_nov.value(), cfg.PACKET_SENSITIVITY_PENALTIES.get("novelty_new", 0.8)): changed = True
        if differs(self._pkt_pen_fail.value(), cfg.PACKET_SENSITIVITY_PENALTIES.get("high_failure_ratio", 0.8)): changed = True
        if differs(self._pkt_fail_thr.value(), cfg.PACKET_HIGH_FAILURE_RATIO_THRESHOLD): changed = True

        if differs(self._ps_k.value(), cfg.PORT_SCAN_K): changed = True
        if self._ps_min_port.value() != cfg.PORT_SCAN_MIN_PORT_SCAN_LIMIT: changed = True
        if self._ps_min_host.value() != cfg.PORT_SCAN_MIN_HOST_SCAN_LIMIT: changed = True
        if differs(self._ps_pen_nov.value(), cfg.PORT_SCAN_SENSITIVITY_PENALTIES.get("novelty_new", 0.8)): changed = True
        if differs(self._ps_pen_fail.value(), cfg.PORT_SCAN_SENSITIVITY_PENALTIES.get("high_failure_ratio", 0.8)): changed = True
        if differs(self._ps_fail_thr.value(), cfg.PORT_SCAN_HIGH_FAILURE_RATIO_THRESHOLD): changed = True
        if self._ps_static_ports.value() not in cfg.PORT_SCAN_STATIC_THRESHOLD_PORTS: changed = True

        if differs(self._an_std_floor.value(), cfg.ANOMALY_STD_FLOOR): changed = True
        if self._an_min_samp.value() != cfg.ANOMALY_MIN_BASELINE_SAMPLES: changed = True
        if differs(self._an_del_syn.value(), cfg.ANOMALY_MIN_DELTAS.get("syn_count", 20.0)): changed = True
        if differs(self._an_del_ports.value(), cfg.ANOMALY_MIN_DELTAS.get("unique_ports", 10.0)): changed = True
        if differs(self._an_del_dests.value(), cfg.ANOMALY_MIN_DELTAS.get("unique_destinations", 10.0)): changed = True
        if differs(self._an_del_pkts.value(), cfg.ANOMALY_MIN_DELTAS.get("packet_count", 1000.0)): changed = True

        self._apply_btn.setEnabled(changed)

    # ------------------------------------------------------------------
    # Engine wiring
    # ------------------------------------------------------------------

    def set_engine(self, engine) -> None:
        """Call when the engine is started or stopped."""
        self._engine = engine

    # ------------------------------------------------------------------
    # Apply / Reset
    # ------------------------------------------------------------------

    def _apply(self) -> None:
        """
        Push all spin-box values to:
          1. The live detector instances (if the engine is running).
          2. The config module (so a subsequent Start reads the new values).
          3. ids_settings.json (for persistence across process restarts).
        """
        # ── Collect new values ────────────────────────────────────────────────
        pkt_penalties = {
            "novelty_new":        round(self._pkt_pen_nov.value(), 4),
            "high_failure_ratio": round(self._pkt_pen_fail.value(), 4),
        }
        ps_penalties = {
            "novelty_new":        round(self._ps_pen_nov.value(), 4),
            "high_failure_ratio": round(self._ps_pen_fail.value(), 4),
        }
        an_deltas = {
            "syn_count":           self._an_del_syn.value(),
            "unique_ports":        self._an_del_ports.value(),
            "unique_destinations": self._an_del_dests.value(),
            "packet_count":        self._an_del_pkts.value(),
        }

        # ── 1. Update config module (in-process) ──────────────────────────────
        config.PACKET_K                          = self._pkt_k.value()
        config.PACKET_MIN_GLOBAL_THRESHOLD       = self._pkt_min_thr.value()
        config.PACKET_WINDOW                     = self._pkt_window.value()
        config.PACKET_SENSITIVITY_PENALTIES      = pkt_penalties
        config.PACKET_HIGH_FAILURE_RATIO_THRESHOLD = self._pkt_fail_thr.value()

        config.PORT_SCAN_K                           = self._ps_k.value()
        config.PORT_SCAN_MIN_PORT_SCAN_LIMIT         = self._ps_min_port.value()
        config.PORT_SCAN_MIN_HOST_SCAN_LIMIT         = self._ps_min_host.value()
        config.PORT_SCAN_SENSITIVITY_PENALTIES       = ps_penalties
        config.PORT_SCAN_HIGH_FAILURE_RATIO_THRESHOLD = self._ps_fail_thr.value()
        config.PORT_SCAN_STATIC_THRESHOLD_PORTS      = {self._ps_static_ports.value()}

        config.ANOMALY_STD_FLOOR            = self._an_std_floor.value()
        config.ANOMALY_MIN_BASELINE_SAMPLES = self._an_min_samp.value()
        config.ANOMALY_MIN_DELTAS           = an_deltas

        # ── 2. Push to live detector instances (atomic writes) ────────────────
        if self._engine is not None:
            pt = self._engine.packet_threshold
            pt.k                             = config.PACKET_K
            pt.min_global_threshold          = config.PACKET_MIN_GLOBAL_THRESHOLD
            pt.WINDOW                        = config.PACKET_WINDOW
            # Dict replacement — atomic under CPython's GIL
            pt.sensitivity_penalties         = dict(pkt_penalties)
            pt.high_failure_ratio_threshold  = config.PACKET_HIGH_FAILURE_RATIO_THRESHOLD

            ps = self._engine.port_scan
            ps.k                             = config.PORT_SCAN_K
            ps.min_port_scan_limit           = config.PORT_SCAN_MIN_PORT_SCAN_LIMIT
            ps.min_host_scan_limit           = config.PORT_SCAN_MIN_HOST_SCAN_LIMIT
            ps.sensitivity_penalties         = dict(ps_penalties)
            ps.high_failure_ratio_threshold  = config.PORT_SCAN_HIGH_FAILURE_RATIO_THRESHOLD
            # Set replacement — atomic under CPython's GIL
            ps.static_threshold_ports        = {self._ps_static_ports.value()}

            ad = self._engine.anomaly_detector
            if ad is not None:
                ad.std_floor             = config.ANOMALY_STD_FLOOR
                ad.min_baseline_samples  = config.ANOMALY_MIN_BASELINE_SAMPLES
                # Dict replacement — atomic under CPython's GIL
                ad.min_deltas            = dict(an_deltas)

        # ── 3. Persist to JSON ────────────────────────────────────────────────
        save_settings({
            "PACKET_K":                            config.PACKET_K,
            "PACKET_MIN_GLOBAL_THRESHOLD":         config.PACKET_MIN_GLOBAL_THRESHOLD,
            "PACKET_WINDOW":                       config.PACKET_WINDOW,
            "PACKET_SENSITIVITY_PENALTIES":        pkt_penalties,
            "PACKET_HIGH_FAILURE_RATIO_THRESHOLD": config.PACKET_HIGH_FAILURE_RATIO_THRESHOLD,

            "PORT_SCAN_K":                             config.PORT_SCAN_K,
            "PORT_SCAN_MIN_PORT_SCAN_LIMIT":           config.PORT_SCAN_MIN_PORT_SCAN_LIMIT,
            "PORT_SCAN_MIN_HOST_SCAN_LIMIT":           config.PORT_SCAN_MIN_HOST_SCAN_LIMIT,
            "PORT_SCAN_SENSITIVITY_PENALTIES":         ps_penalties,
            "PORT_SCAN_HIGH_FAILURE_RATIO_THRESHOLD":  config.PORT_SCAN_HIGH_FAILURE_RATIO_THRESHOLD,
            # Sets are not JSON-serialisable — store as sorted list
            "PORT_SCAN_STATIC_THRESHOLD_PORTS":        sorted(config.PORT_SCAN_STATIC_THRESHOLD_PORTS),

            "ANOMALY_STD_FLOOR":            config.ANOMALY_STD_FLOOR,
            "ANOMALY_MIN_BASELINE_SAMPLES": config.ANOMALY_MIN_BASELINE_SAMPLES,
            "ANOMALY_MIN_DELTAS":           an_deltas,
        })
        
        self._check_changes()
        self._success_lbl.show()
        QTimer.singleShot(2500, self._success_lbl.hide)

    def _reset_defaults(self) -> None:
        """
        Reset all spin-boxes to the hard-coded default values from config's
        original definitions (not from the current config module state, which
        may already have been overridden).  Does NOT apply or persist —
        the user must click Apply to commit.
        """
        self._pkt_k.setValue(2.0)
        self._pkt_min_thr.setValue(1000)
        self._pkt_window.setValue(10)
        self._pkt_pen_nov.setValue(0.8)
        self._pkt_pen_fail.setValue(0.8)
        self._pkt_fail_thr.setValue(0.6)

        self._ps_k.setValue(2.0)
        self._ps_min_port.setValue(10)
        self._ps_min_host.setValue(10)
        self._ps_pen_nov.setValue(0.8)
        self._ps_pen_fail.setValue(0.8)
        self._ps_fail_thr.setValue(0.6)
        self._ps_static_ports.setValue(443)

        self._an_std_floor.setValue(1.0)
        self._an_min_samp.setValue(10)
        self._an_del_syn.setValue(20.0)
        self._an_del_ports.setValue(10.0)
        self._an_del_dests.setValue(10.0)
        self._an_del_pkts.setValue(1000.0)
        
        self._check_changes()
