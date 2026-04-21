# main.py
import threading
from capturing.interface_utils import get_relevant_interfaces, banner
from capturing.packet_capture import PacketCapture
from engine.ids_engine import DetectionEngine
from database.init_db import initialize_database
from baseline.data_collector import LiveMetricsCollector
from baseline.anomaly_detector import AnomalyDetector


def main():
    initialize_database()

    ifaces = get_relevant_interfaces()
    banner(ifaces)

    # Start packet capture — tshark needs the interface name explicitly
    packet_capture = PacketCapture()
    packet_capture.start_capture([iface["index"] for iface in ifaces])

    # AnomalyDetector is pure detection + persistence; no gate knowledge.
    anomaly_detector = AnomalyDetector()

    # DetectionEngine owns the AlertGate and orchestrates all gating,
    # saving, and printing for both rule-based and anomaly alerts.
    engine = DetectionEngine(
        packet_capture=packet_capture,
        anomaly_detector=anomaly_detector,
    )

    # LiveMetricsCollector calls engine.process_anomaly() — engine is the
    # single orchestration point, so no direct anomaly_detector reference needed.
    metrics_collector = LiveMetricsCollector(packet_capture, engine)
    collector_thread = threading.Thread(
        target=metrics_collector.run,
        daemon=True,
        name="MetricsCollector",
    )
    collector_thread.start()
    print("Live metrics collector started.")

    # Detection engine runs on the main thread
    try:
        engine.run()
    except KeyboardInterrupt:
        print("\nStopping IDS...")
        metrics_collector.stop()
        packet_capture.stop()


if __name__ == "__main__":
    main()