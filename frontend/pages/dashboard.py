"""
frontend/pages/dashboard.py

All widget logic lives in frontend/widgets/.
"""

import queue
import threading

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton
from PySide6.QtCore import Qt

from frontend.theme import SPACING, LAYOUT_SIZES
from frontend.widgets.shared.helpers import _lbl
from frontend.widgets.alerts.alert_feed import AlertFeed
from frontend.widgets.hosts.host_metrics import HostMetricsArea
from frontend.widgets.logs.logs_panel import LogsPanel
from frontend.widgets.kpi.kpi_tile import KpiTile
from frontend.widgets.kpi.kpi_refresher import KpiRefresher
from frontend.widgets.bottom_bar import BottomBar
from frontend.widgets.bottom_bar_refresher import BottomBarRefresher

def _start_ids(alert_queue: queue.Queue) -> dict:
    """Start the full IDS stack and return a handle dict."""
    from database.init_db import initialize_database
    from capturing.interface_utils import get_relevant_interfaces
    from capturing.packet_capture import PacketCapture
    from engine.ids_engine import DetectionEngine
    from baseline.anomaly_detector import AnomalyDetector
    from baseline.data_collector import LiveMetricsCollector

    initialize_database()

    ifaces = get_relevant_interfaces()
    packet_capture = PacketCapture()
    iface_names = [iface["index"] for iface in ifaces]
    packet_capture.start_capture(iface_names)

    anomaly_detector = AnomalyDetector()

    engine = DetectionEngine(
        packet_capture=packet_capture,
        anomaly_detector=anomaly_detector,
        alert_queue=alert_queue,
    )

    metrics_collector = LiveMetricsCollector(packet_capture, engine)

    engine.collector = metrics_collector

    engine_thread = threading.Thread(
        target=engine.run, daemon=True, name="DetectionEngine"
    )
    engine_thread.start()

    collector_thread = threading.Thread(
        target=metrics_collector.run, daemon=True, name="MetricsCollector"
    )
    collector_thread.start()

    return {
        "engine":            engine,
        "packet_capture":    packet_capture,
        "metrics_collector": metrics_collector,
        "collector_thread":  collector_thread,
    }


def _stop_ids(ids: dict) -> None:
    """Graceful shutdown of a running IDS handle dict."""
    ids["metrics_collector"].stop()
    ids["collector_thread"].join(timeout=5)
    ids["packet_capture"].stop()


class DashboardPage(QWidget):

    # Static tile definitions: (title, unit, value_name, snapshot_key)
    # snapshot_key maps to the corresponding key in kpi_snapshot().
    # Queue Depth is a special case — it combines two snapshot keys.
    _KPI_DEFS = [
        ("Alerts (60 s)", "events",  "kpiValueRed",    "alerts_60s"),
        ("Active Hosts",  "online",  "kpiValueAccent",  "active_hosts"),
        ("Queue Depth",   "pkts",    "kpiValueAmber",   "_queue_depth"),  # computed
        ("Capture State", "",        "kpiValueGreen",   "capture_state"),
    ]

    def __init__(self, alert_queue=None, log_queue=None, engine=None, parent=None):
        super().__init__(parent)
        self.setObjectName("dashboardPage")
        self._engine = engine
        self._alert_queue = alert_queue
        self._log_queue = log_queue
        self._ids_running = engine is not None
        # _ids_handle is populated when DashboardPage owns the IDS lifecycle
        # (i.e. after the first Stop/Start or Restart cycle). Before that,
        # app.py owns the handle; we track running state via _ids_running only.
        self._ids_handle: dict | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(
            SPACING["none"], SPACING["none"], SPACING["none"], SPACING["none"]
        )
        root.setSpacing(SPACING["xs"])

        root.addWidget(self._build_page_header())

        content = QWidget()
        content.setObjectName("dashContent")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(
            SPACING["xl"], SPACING["lg"], SPACING["xl"], SPACING["none"]
        )
        cl.setSpacing(SPACING["lg"])

        cl.addLayout(self._build_kpi_strip())

        center = QHBoxLayout()
        center.setSpacing(SPACING["lg"])
        center.addWidget(AlertFeed(alert_queue=alert_queue), stretch=1)
        self._host_metrics = HostMetricsArea(engine=engine)
        center.addWidget(self._host_metrics, stretch=1)
        cl.addLayout(center, stretch=1)

        cl.addWidget(LogsPanel(log_queue=self._log_queue))

        root.addWidget(content, stretch=1)
        self._bottom_bar = BottomBar()
        root.addWidget(self._bottom_bar)

        # Start live KPI polling only when a real engine is present.
        self._refresher = KpiRefresher(self._engine, interval_ms=1000, parent=self)
        self._refresher.refreshed.connect(self._update_kpis)
        if self._engine is not None:
            self._refresher.start()

        _pc = self._engine.packet_capture if self._engine is not None else None
        self._bar_refresher = BottomBarRefresher(_pc, parent=self)
        self._bar_refresher.signal.connect(self._update_bottom_bar)
        if self._engine is not None:
            self._bar_refresher.start()
    # ------------------------------------------------------------------
    # Page header
    # ------------------------------------------------------------------

    def _build_page_header(self) -> QWidget:
        header = QWidget()
        header.setObjectName("pageHeader")
        header.setFixedHeight(LAYOUT_SIZES["page_header_h"])
        row = QHBoxLayout(header)
        row.setContentsMargins(
            SPACING["xxl"], SPACING["none"], SPACING["xxl"], SPACING["none"]
        )
        row.addWidget(_lbl("DASHBOARD", "pageHeaderTitle"))
        row.addStretch()
        return header

    def _build_kpi_strip(self) -> QHBoxLayout:
        """
        Build the four KPI tiles.  The Capture State tile gets two control
        buttons (Stop/Start and Restart) placed immediately to its right.
        """
        strip = QHBoxLayout()
        strip.setSpacing(SPACING["md"])

        self._kpi_tiles: list[KpiTile] = []
        placeholder = "—"

        for i, (title, unit, value_name, _) in enumerate(self._KPI_DEFS):
            tile = KpiTile(title, placeholder, unit, value_name)
            self._kpi_tiles.append(tile)
            strip.addWidget(tile)

            # Inject control buttons immediately after the Capture State tile
            # (last entry in _KPI_DEFS).
            if i == len(self._KPI_DEFS) - 1:
                strip.addLayout(self._build_control_buttons())

        return strip

    def _build_control_buttons(self) -> QVBoxLayout:
        """
        Return a compact vertical layout holding the Stop/Start and Restart
        buttons, sized to fit within the KPI strip height.
        """
        btn_layout = QVBoxLayout()
        btn_layout.setSpacing(SPACING["xs"])
        btn_layout.setContentsMargins(
            SPACING["none"], SPACING["sm"], SPACING["none"], SPACING["sm"]
        )

        self._toggle_btn = QPushButton("Stop")
        self._toggle_btn.setObjectName("idsStopBtn")
        self._toggle_btn.setFixedWidth(80)
        self._toggle_btn.clicked.connect(self._toggle_ids)

        self._restart_btn = QPushButton("Restart")
        self._restart_btn.setObjectName("idsRestartBtn")
        self._restart_btn.setFixedWidth(80)
        self._restart_btn.clicked.connect(self._restart_ids)

        btn_layout.addWidget(self._toggle_btn)
        btn_layout.addWidget(self._restart_btn)

        return btn_layout

    # ------------------------------------------------------------------
    # IDS lifecycle control
    # ------------------------------------------------------------------

    def _toggle_ids(self) -> None:
        """Stop a running IDS, or start a stopped one."""
        if self._ids_running:
            self._do_stop()
        else:
            self._do_start()

    def _restart_ids(self) -> None:
        """Stop (if running) then start fresh."""
        if self._ids_running:
            self._do_stop()
        self._do_start()

    def _do_stop(self) -> None:
        """Tear down the IDS stack and update UI to reflect stopped state."""
        # Stop refreshers first so they don't read a dying engine.
        self._refresher.stop()
        self._refresher.set_engine(None)
        self._bar_refresher.stop()
        self._bar_refresher.set_packet_capture(None)
        self._host_metrics.set_engine(None)

        if self._ids_handle is not None:
            _stop_ids(self._ids_handle)
            self._ids_handle = None
        elif self._engine is not None and hasattr(self._engine, "packet_capture"):
            pc = self._engine.packet_capture
            if pc is not None:
                self._engine.packet_capture.metrics_collector = None
                pc.stop()

        self._engine = None
        self._ids_running = False

        self._toggle_btn.setText("Start")
        self._toggle_btn.setObjectName("idsStartBtn")
        self._toggle_btn.style().unpolish(self._toggle_btn)
        self._toggle_btn.style().polish(self._toggle_btn)
        self._restart_btn.setEnabled(True)
        self._set_kpis_stopped()

    def _do_start(self) -> None:
        """Launch a fresh IDS stack and wire it into the existing UI."""
        handle = _start_ids(self._alert_queue)
        self._ids_handle = handle
        self._engine = handle["engine"]
        self._ids_running = True

        # Point both refreshers at the new engine and resume polling.
        self._refresher.set_engine(self._engine)
        self._refresher.start()
        self._bar_refresher.set_packet_capture(self._engine.packet_capture)
        self._bar_refresher.start()
        self._host_metrics.set_engine(self._engine)

        self._toggle_btn.setText("Stop")
        self._toggle_btn.setObjectName("idsStopBtn")
        self._toggle_btn.style().unpolish(self._toggle_btn)
        self._toggle_btn.style().polish(self._toggle_btn)

    def _set_kpis_stopped(self) -> None:
        """Push placeholder values into all tiles when the engine is stopped."""
        for tile, (_, _, _, key) in zip(self._kpi_tiles, self._KPI_DEFS):
            if key == "capture_state":
                tile.set_value("STOPPED")
            elif key == "_queue_depth":
                tile.set_value("0 / 0")
            else:
                tile.set_value("—")

    def _update_bottom_bar(self, status: dict) -> None:
        """Unpack the dict emitted by BottomBarRefresher and forward to the bar."""
        self._bottom_bar.update_status(
            last_tick=status.get("last_tick", "—"),
            stall=bool(status.get("stall", False)),
        )

    def _update_kpis(self, snapshot: dict) -> None:
        """Receive a fresh snapshot dict and push each value into its tile."""
        for tile, (_, _, _, key) in zip(self._kpi_tiles, self._KPI_DEFS):
            if key == "_queue_depth":
                eq = snapshot.get("engine_q", 0)
                cq = snapshot.get("collector_q", 0)
                value = f"{eq} / {cq}"
            else:
                raw = snapshot.get(key, "—")
                value = str(raw)

            tile.set_value(value)