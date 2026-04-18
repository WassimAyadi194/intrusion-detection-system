#ids_engine.py
import queue
import sqlite3
import time
from detections.port_scan import PortScanDetector
from detections.connection_tracking import ConnectionTracker
from detections.packets_threshold import PacketThresholdDetector

DB_NAME = "ids.db"


class DetectionEngine:
    def __init__(self, packet_capture=None):
        self.port_scan = PortScanDetector()
        self.connection_tracker = ConnectionTracker()
        self.packet_threshold = PacketThresholdDetector()
        self.packet_capture = packet_capture

    def _save_alerts(self, alerts: list[dict]):
        """Persist rule-based alert dicts to the alerts table."""
        if not alerts:
            return
        conn = sqlite3.connect(DB_NAME, timeout=5)
        cursor = conn.cursor()
        cursor.executemany("""
            INSERT INTO alerts
                (host_ip, metric, value, baseline_avg, baseline_std,
                 severity, timestamp, description)
            VALUES
                (:host_ip, :metric, :value, :baseline_avg, :baseline_std,
                 :severity, :timestamp, :description)
        """, alerts)
        conn.commit()
        conn.close()

    def _make_alert(self, host_ip: str, metric: str, description: str, severity: str = "HIGH") -> dict:
        """Build an alert dict compatible with the alerts table schema."""
        return {
            "host_ip":      host_ip,
            "metric":       metric,
            "value":        0.0,   # rule-based alerts have no numeric value
            "baseline_avg": 0.0,
            "baseline_std": 0.0,
            "severity":     severity,
            "timestamp":    int(time.time()),
            "description":  description,
        }

    def process_packet(self, pkt):
        alert_dicts = []

        # --- Port scan ---
        result = self.port_scan.analyze_packet(pkt)
        if result:
            src = pkt["IP"].src
            for msg in result:
                alert_dicts.append(self._make_alert(src, "port_scan", msg.strip(), "HIGH"))

        # --- Connection tracking ---
        result = self.connection_tracker.analyze_packet(pkt)
        if result:
            src = pkt["IP"].src
            for msg in result:
                # Only persist actual detections, not routine "Connection detected" noise
                severity = "LOW" if "detected" in msg else "MEDIUM"
                alert_dicts.append(self._make_alert(src, "connection", msg.strip(), severity))

        # --- Packet flood ---
        result = self.packet_threshold.analyze_packet(pkt)
        if result:
            src = pkt["IP"].src
            for msg in result:
                alert_dicts.append(self._make_alert(src, "packet_flood", msg.strip(), "CRITICAL"))

        return alert_dicts

    def run(self):
        if self.packet_capture is None:
            raise RuntimeError("PacketCapture instance not provided to DetectionEngine.")

        while True:
            try:
                pkt = self.packet_capture.engine_queue.get(timeout=1)
                alerts = self.process_packet(pkt)
                if alerts:
                    self._save_alerts(alerts)
                    for a in alerts:
                        print(f"[{a['severity']}] {a['metric'].upper()} | {a['description']}")

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                break