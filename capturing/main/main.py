# main.py
import threading
from capturing.interface_utils import get_relevant_interfaces, banner
from capturing.packet_capture import PacketCapture
from engine.ids_engine import DetectionEngine
from database.init_db import initialize_database
from baseline.data_collector import LiveMetricsCollector
from baseline.anomaly_detector import AnomalyDetector
from logs.ids_logger import get_logger, shutdown as shutdown_logger

log = get_logger(__name__)


def main():
    initialize_database()

    ifaces = get_relevant_interfaces()
    banner(ifaces)  # prints interface names to stdout

    packet_capture = PacketCapture()
    iface_names = [iface["index"] for iface in ifaces]
    packet_capture.start_capture(iface_names)

    anomaly_detector = AnomalyDetector()

    engine = DetectionEngine(
        packet_capture=packet_capture,
        anomaly_detector=anomaly_detector,
    )

    metrics_collector = LiveMetricsCollector(packet_capture, engine)
    collector_thread = threading.Thread(
        target=metrics_collector.run,
        daemon=True,
        name="MetricsCollector",
    )
    collector_thread.start()

    log.info("IDS started — interfaces: %s", ", ".join(str(i["index"]) for i in ifaces))

    try:
        engine.run()
    except KeyboardInterrupt:
        pass
    finally:
        log.info("Shutdown requested — stopping IDS.")
        metrics_collector.stop()
        collector_thread.join(timeout=5)
        packet_capture.stop()
        log.info("IDS shut down cleanly.")
        shutdown_logger()


if __name__ == "__main__":
    main()