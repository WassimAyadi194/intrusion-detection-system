from detections.port_scan import PortScanDetector
from detections.connection_tracking import ConnectionTracker
from detections.packets_threshold import PacketThresholdDetector
import queue


class DetectionEngine:
    def __init__(self, packet_capture=None):
        self.port_scan = PortScanDetector()
        self.connection_tracker = ConnectionTracker()
        self.packet_threshold = PacketThresholdDetector()
        self.packet_capture = packet_capture

    def process_packet(self, pkt):
        alerts = []

        result = self.port_scan.analyze_packet(pkt)
        if result:
            alerts.extend(result)

        result = self.connection_tracker.analyze_packet(pkt)
        if result:
            alerts.extend(result)

        result = self.packet_threshold.analyze_packet(pkt)
        if result:
            alerts.extend(result)

        return alerts

    def run(self):
        if self.packet_capture is None:
            raise RuntimeError("PacketCapture instance not provided to DetectionEngine.")

        while True:
            try:
                pkt = self.packet_capture.engine_queue.get(timeout=1)
                alerts = self.process_packet(pkt)
                if alerts:
                    for alert in alerts:
                        print(alert)

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                break