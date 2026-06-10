"""
frontend/pages/dashboard.py

All widget logic lives in frontend/widgets/.
"""

import queue

from engine.launcher import start_ids as _start_ids, stop_ids as _stop_ids

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton
from PySide6.QtCore import Qt, Signal, QTimer, QPropertyAnimation, QEasingCurve, QRect
from PySide6.QtGui import QResizeEvent, QShowEvent

from frontend.theme import SPACING, LAYOUT_SIZES
from frontend.widgets.shared.helpers import _lbl
from frontend.widgets.alerts.alert_feed import AlertFeed
from frontend.widgets.hosts.host_metrics import HostMetricsArea
from frontend.widgets.logs.logs_panel import LogsPanel
from frontend.widgets.kpi.kpi_tile import KpiTile
from frontend.widgets.kpi.kpi_refresher import KpiRefresher
from frontend.widgets.bottom_bar import BottomBar
from frontend.widgets.bottom_bar_refresher import BottomBarRefresher
from frontend.widgets.shared.export_dialog import ExportDialog
from reports.csv_generator import CSVReportGenerator


class DashboardPage(QWidget):

    engine_changed = Signal(object)

    _KPI_DEFS = [
        ("Alerts (60 s)", "events",  "kpiValueRed",    "alerts_60s"),
        ("Active Hosts",  "online",  "kpiValueAccent",  "active_hosts"),
        ("Queue Depth",   "pkts",    "kpiValueAmber",   "_queue_depth"),
        ("Capture State", "",        "kpiValueGreen",   "capture_state"),
    ]

    def __init__(self, alert_queue=None, log_queue=None, engine=None, parent=None):
        super().__init__(parent)
        self.setObjectName("dashboardPage")
        self._engine = engine
        self._alert_queue = alert_queue
        self._log_queue = log_queue
        self._ids_running = engine is not None
        self._ids_handle: dict | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(
            SPACING["none"], SPACING["none"], SPACING["none"], SPACING["none"]
        )
        root.setSpacing(SPACING["xs"])

        root.addWidget(self._build_page_header())

        # Use a plain QWidget for content — LogsPanel floats over DashboardPage
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

        # Reserve space at the bottom of the content area equal to the
        # logs-toggle button height.  The LogsPanel floats *over* this gap,
        # so AlertFeed / HostMetrics never render beneath the button.
        cl.addSpacing(LAYOUT_SIZES["panel_header_h"])

        # LogsPanel is a direct child of DashboardPage — NOT in any layout.
        # It floats freely; its geometry is managed by _reposition_logs / _toggle_logs.
        self._logs_expanded = False
        self._logs_anim: QPropertyAnimation | None = None
        self._logs_panel = LogsPanel(log_queue=self._log_queue, parent=self)
        self._logs_panel.panel_toggled.connect(self._toggle_logs)

        root.addWidget(content, stretch=1)
        self._bottom_bar = BottomBar()
        root.addWidget(self._bottom_bar)

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
    # Floating LogsPanel positioning
    # ------------------------------------------------------------------

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        # Defer one tick so the layout has finished computing geometry
        # before we read self._bottom_bar.pos().
        QTimer.singleShot(0, self._reposition_logs)

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._reposition_logs()

    def _reposition_logs(self) -> None:
        """Pin the LogsPanel so its toggle button sits just above the BottomBar."""
        bar_y = self._bottom_bar.pos().y()
        if bar_y <= 0:
            return  # layout not ready yet — showEvent will retry
        w = self.width()
        toggle_h = LAYOUT_SIZES["panel_header_h"]
        panel_h  = LAYOUT_SIZES["logs_panel_h"] + toggle_h
        # When collapsed only the toggle is visible (height = toggle_h).
        # When expanded the full panel is visible (height = panel_h).
        h = panel_h if self._logs_expanded else toggle_h
        self._logs_panel.setGeometry(0, bar_y - h, w, h)
        self._logs_panel.raise_()

    def _toggle_logs(self, expanding: bool) -> None:
        """Animate the LogsPanel geometry when the user clicks the toggle button."""
        bar_y = self._bottom_bar.pos().y()
        w = self.width()
        toggle_h = LAYOUT_SIZES["panel_header_h"]
        panel_h  = LAYOUT_SIZES["logs_panel_h"] + toggle_h

        self._logs_expanded = expanding

        start_rect = self._logs_panel.geometry()
        if expanding:
            end_rect = QRect(0, bar_y - panel_h, w, panel_h)
        else:
            end_rect = QRect(0, bar_y - toggle_h, w, toggle_h)

        if self._logs_anim is not None:
            self._logs_anim.stop()

        anim = QPropertyAnimation(self._logs_panel, b"geometry", self)
        anim.setStartValue(start_rect)
        anim.setEndValue(end_rect)
        anim.setDuration(220)
        anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
        if not expanding:
            anim.finished.connect(self._logs_panel.on_collapse_finished)
        anim.start()
        self._logs_anim = anim
        self._logs_panel.raise_()

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
        row.addWidget(_lbl("DASHBOARD", "pageHeaderTitle"))
        row.addStretch()

        self._export_btn = QPushButton("Export CSV")
        self._export_btn.setObjectName("secondaryBtn")
        self._export_btn.clicked.connect(self._show_export_dialog)
        row.addWidget(self._export_btn)

        return header

    def _show_export_dialog(self):
        from PySide6.QtWidgets import QMessageBox
        dialog = ExportDialog(self)
        if dialog.exec() == ExportDialog.DialogCode.Accepted:
            tables = dialog.get_selected_tables()
            if tables:
                generator = CSVReportGenerator()
                results = generator.generate_selected(tables)
                if results:
                    msg = "\n".join(results)
                    QMessageBox.information(self, "Export Results", msg)

    def _build_kpi_strip(self) -> QHBoxLayout:
        strip = QHBoxLayout()
        strip.setSpacing(SPACING["md"])

        self._kpi_tiles: list[KpiTile] = []
        placeholder = "—"

        for i, (title, unit, value_name, _) in enumerate(self._KPI_DEFS):
            tile = KpiTile(title, placeholder, unit, value_name)
            self._kpi_tiles.append(tile)
            strip.addWidget(tile)

            if i == len(self._KPI_DEFS) - 1:
                strip.addLayout(self._build_control_buttons())

        return strip

    def _build_control_buttons(self) -> QVBoxLayout:
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
        if self._ids_running:
            self._do_stop()
        else:
            self._do_start()

    def _restart_ids(self) -> None:
        if self._ids_running:
            self._do_stop()
        self._do_start()

    def _do_stop(self) -> None:
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
        self.engine_changed.emit(None)

        self._toggle_btn.setText("Start")
        self._toggle_btn.setObjectName("idsStartBtn")
        self._toggle_btn.style().unpolish(self._toggle_btn)
        self._toggle_btn.style().polish(self._toggle_btn)
        self._restart_btn.setEnabled(True)
        self._set_kpis_stopped()

    def _do_start(self) -> None:
        handle = _start_ids(self._alert_queue)
        self._ids_handle = handle
        self._engine = handle["engine"]
        self._ids_running = True
        self.engine_changed.emit(self._engine)

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
        for tile, (_, _, _, key) in zip(self._kpi_tiles, self._KPI_DEFS):
            if key == "capture_state":
                tile.set_value("STOPPED")
                tile.set_color_class("kpiValueRed")
            elif key == "_queue_depth":
                tile.set_value("0 / 0")
            else:
                tile.set_value("—")

    def _update_bottom_bar(self, status: dict) -> None:
        self._bottom_bar.update_status(
            last_tick=status.get("last_tick", "—"),
            stall=bool(status.get("stall", False)),
        )

    def _update_kpis(self, snapshot: dict) -> None:
        for tile, (_, _, _, key) in zip(self._kpi_tiles, self._KPI_DEFS):
            if key == "_queue_depth":
                eq = snapshot.get("engine_q", 0)
                cq = snapshot.get("collector_q", 0)
                value = f"{eq} / {cq}"
            else:
                raw = snapshot.get(key, "—")
                value = str(raw)

            tile.set_value(value)
            
            # Revert the color to green if it was running.
            if key == "capture_state" and value != "—":
                tile.set_color_class("kpiValueGreen")