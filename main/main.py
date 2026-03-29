import threading
from capturing.interface_utils import get_active_interface
from capturing.packet_capture import PacketCapture
from engine.ids_engine import DetectionEngine
from database.init_db import initialize_database
from baseline.data_collector import LiveMetricsCollector


def main():
    # Initialize DB (creates tables if they don't exist)
    initialize_database()

    iface, ip = get_active_interface()
    if iface is None:
        raise SystemExit("IDS startup failed: no active interface detected.")

    print(f"IDS starting on interface: {iface}")

    # Start packet capture
    packet_capture = PacketCapture()
    packet_capture.start_capture()

    # Start live metrics collector in a background daemon thread
    # It shares the same PacketCapture queue as the detection engine
    metrics_collector = LiveMetricsCollector(packet_capture)
    collector_thread = threading.Thread(
        target=metrics_collector.run,
        daemon=True,
        name="MetricsCollector"
    )
    collector_thread.start()
    print("Live metrics collector started.")

    # IDS engine runs in main loop reading from queue
    engine = DetectionEngine(packet_capture)
    try:
        engine.run()
    except KeyboardInterrupt:
        print("\nStopping IDS...")
        metrics_collector.stop()
        packet_capture.stop()


if __name__ == "__main__":
    main()