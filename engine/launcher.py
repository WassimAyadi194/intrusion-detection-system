"""
engine/launcher.py
──────────────────
Shared IDS lifecycle helpers.

Imported by both frontend.app (initial startup) and
frontend.pages.dashboard (Stop / Start / Restart cycles) so the
logic is never duplicated.
"""

import queue
import threading
import shutil


def start_ids(alert_queue: queue.Queue) -> dict:
    """Start the full IDS stack and return a handle dict."""
    from database.init_db import initialize_database
    from capturing.interface_utils import get_relevant_interfaces

    if not shutil.which("tshark"):
        raise RuntimeError("tshark not found — install Wireshark and add it to PATH.")

    ifaces = get_relevant_interfaces()
    if not ifaces:
        raise RuntimeError("No active network interfaces found.")

    from capturing.packet_capture import PacketCapture
    from engine.ids_engine import DetectionEngine
    from baseline.anomaly_detector import AnomalyDetector
    from baseline.data_collector import LiveMetricsCollector

    initialize_database()

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


def stop_ids(ids: dict) -> None:
    """Graceful shutdown of a running IDS handle dict."""
    ids["metrics_collector"].stop()
    ids["collector_thread"].join(timeout=5)
    ids["packet_capture"].stop()
