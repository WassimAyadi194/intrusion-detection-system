#main.py
import threading
from capturing.interface_utils import get_relevant_interfaces, banner
from capturing.packet_capture import PacketCapture
from engine.ids_engine import DetectionEngine
from database.init_db import initialize_database
from baseline.data_collector import LiveMetricsCollector


def main():
    initialize_database()

    ifaces = get_relevant_interfaces()
    banner(ifaces)

    # Start packet capture — tshark needs the interface name explicitly
    packet_capture = PacketCapture()
    packet_capture.start_capture([iface["index"] for iface in ifaces])

    # Start live metrics collector in a background daemon thread
    metrics_collector = LiveMetricsCollector(packet_capture)
    collector_thread = threading.Thread(
        target=metrics_collector.run,
        daemon=True,
        name="MetricsCollector",
    )
    collector_thread.start()
    print("Live metrics collector started.")

    # Detection engine runs on the main thread
    engine = DetectionEngine(packet_capture)
    try:
        engine.run()
    except KeyboardInterrupt:
        print("\nStopping IDS...")
        metrics_collector.stop()
        packet_capture.stop()


if __name__ == "__main__":
    main()