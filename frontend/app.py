"""
Entry point for the IDS frontend.

Run from the project root:
    python -m frontend.app
"""
import sys
import signal
import queue
import threading
import importlib

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QShortcut, QKeySequence

from frontend.main_window import MainWindow
import frontend.styles as styles
import frontend.theme as theme


def apply_styles(app):
    importlib.reload(theme)
    importlib.reload(styles)
    app.setStyleSheet("")
    app.setStyleSheet(styles.STYLESHEET)


def _start_ids(alert_queue: queue.Queue) -> dict:

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

    # Build the engine first so LiveMetricsCollector can reference it.
    # Wire collector back into engine afterwards — both are mutually dependent.
    engine = DetectionEngine(
        packet_capture=packet_capture,
        anomaly_detector=anomaly_detector,
        alert_queue=alert_queue,
    )

    metrics_collector = LiveMetricsCollector(packet_capture, engine)

    # Attach the collector so engine.host_metrics_snapshot() can read
    # _last_window and produce non-zero pkt_rate values.
    engine.collector = metrics_collector

    engine_thread = threading.Thread(
        target=engine.run,
        daemon=True,
        name="DetectionEngine",
    )
    engine_thread.start()

    collector_thread = threading.Thread(
        target=metrics_collector.run,
        daemon=True,
        name="MetricsCollector",
    )
    collector_thread.start()

    return {
        "engine":            engine,           # exposed for KPI polling
        "packet_capture":    packet_capture,
        "metrics_collector": metrics_collector,
        "collector_thread":  collector_thread,
    }


def _stop_ids(ids: dict) -> None:
    """Graceful shutdown — mirrors the finally block in main.py."""
    ids["metrics_collector"].stop()
    ids["collector_thread"].join(timeout=5)
    ids["packet_capture"].stop()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("HYBRID IDS")

    apply_styles(app)

    # Shared queue: DetectionEngine → AlertFeed (thread-safe)
    alert_queue: queue.Queue = queue.Queue()

    ids = _start_ids(alert_queue)

    # Subscribe a UI log queue so LogsPanel can stream live log records.
    from logs.ids_logger import get_log_queue
    log_queue = get_log_queue()

    window = MainWindow(alert_queue=alert_queue, log_queue=log_queue, engine=ids["engine"])
    window.show()

    # Ctrl+R → reload styles live
    shortcut = QShortcut(QKeySequence("Ctrl+R"), window)
    shortcut.activated.connect(lambda: apply_styles(app))

    # Make Ctrl+C in the terminal trigger a clean Qt shutdown.
    # Qt on Windows swallows SIGINT by default; this restores the expected
    # behaviour without touching any IDS internals.
    signal.signal(signal.SIGINT, lambda *_: app.quit())

    exit_code = app.exec()

    _stop_ids(ids)

    sys.exit(exit_code)

if __name__ == "__main__":
    main()