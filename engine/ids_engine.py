# engine/ids_engine.py
import queue
import sqlite3
import time

from detections.port_scan import PortScanDetector
from detections.connection_tracking import ConnectionTracker
from detections.packets_threshold import PacketThresholdDetector
from detections.alert_gate import AlertGate

DB_NAME = "ids.db"


def _load_baseline_hosts(db_name: str = DB_NAME) -> set[str]:
    """Load all known host IPs from the baseline table once at startup."""
    try:
        conn = sqlite3.connect(db_name, timeout=5)
        cursor = conn.cursor()
        cursor.execute("SELECT host_ip FROM baseline")
        hosts = {row[0] for row in cursor.fetchall()}
        conn.close()
        return hosts
    except sqlite3.Error:
        return set()


class DetectionEngine:
    def __init__(self, packet_capture=None, anomaly_detector=None):
        baseline_hosts = _load_baseline_hosts()

        self.port_scan          = PortScanDetector()
        self.connection_tracker = ConnectionTracker(baseline_hosts=baseline_hosts)
        self.packet_threshold   = PacketThresholdDetector()
        self.packet_capture     = packet_capture
        self.anomaly_detector   = anomaly_detector

        # AlertGate is the single suppression authority for ALL alert types.
        self.alert_gate = AlertGate()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save_alerts(self, alerts: list[dict]):
        """Persist rule-based alert dicts to the alerts table."""
        if not alerts:
            return
        conn = sqlite3.connect(DB_NAME, timeout=5)
        # WAL mode allows the collector thread to read/write simultaneously
        # without blocking the engine thread's writes.
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        cursor.executemany("""
            INSERT INTO alerts
                (host_ip, metric, value, baseline_avg, baseline_std,
                 severity, timestamp, description, novelty)
            VALUES
                (:host_ip, :metric, :value, :baseline_avg, :baseline_std,
                 :severity, :timestamp, :description, :novelty)
        """, alerts)
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Alert normalisation (rule-based detectors → DB schema)
    # ------------------------------------------------------------------

    @staticmethod
    def _to_db_dict(alert: dict) -> dict:
        """
        Convert a unified alert dict into the shape expected by the alerts table.
        Rule-based alerts have no numeric baseline values, so those default to None.
        novelty is populated from connection alerts and left None for all others.
        """
        return {
            "host_ip":      alert["src"],
            "metric":       alert.get("metric") or alert.get("type", ""),
            "value":        None,
            "baseline_avg": None,
            "baseline_std": None,
            "severity":     alert.get("severity", ""),
            "timestamp":    alert.get("timestamp", int(time.time())),
            "description":  alert.get("message", ""),
            "novelty":      alert.get("novelty"),   # None for non-connection alerts
        }

    # ------------------------------------------------------------------
    # Per-packet processing (rule-based detectors)
    # ------------------------------------------------------------------

    def process_packet(self, pkt) -> list[dict]:
        """
        Run all rule-based detectors, gate each raw alert through AlertGate,
        and return the list of allowed unified alert dicts.
        """
        raw_alerts: list[dict] = []

        result = self.port_scan.analyze_packet(pkt)
        if result:
            raw_alerts.extend(result)

        result = self.connection_tracker.analyze_packet(pkt)
        if result:
            raw_alerts.extend(result)

        result = self.packet_threshold.analyze_packet(pkt)
        if result:
            raw_alerts.extend(result)

        # Gate every alert — AlertGate is the only suppression point.
        allowed = []
        for r in raw_alerts:
            a = self.alert_gate.process(r)
            if a:
                allowed.append(a)
        return allowed

    # ------------------------------------------------------------------
    # Anomaly window processing (called by LiveMetricsCollector)
    # ------------------------------------------------------------------

    def process_anomaly(self, host_ip: str, **metrics) -> list[dict]:
        """
        Gate and persist anomaly alerts produced by AnomalyDetector.

        Flow:
            1. AnomalyDetector.analyze() — pure detection, returns raw alerts
            2. AlertGate.process()       — single suppression point
            3. AnomalyDetector.save_alerts() — persist only approved alerts
            4. Print approved alerts
        """
        if self.anomaly_detector is None:
            return []

        raw_alerts = self.anomaly_detector.analyze(host_ip, **metrics)
        if not raw_alerts:
            return []

        allowed = [a for a in (self.alert_gate.process(r) for r in raw_alerts) if a is not None]

        if allowed:
            self.anomaly_detector.save_alerts(allowed)
            for a in allowed:
                print(f"[ANOMALY] {a['severity']} | {a['src']} | {a['message']}")

        return allowed

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self):
        if self.packet_capture is None:
            raise RuntimeError("PacketCapture instance not provided to DetectionEngine.")

        _BATCH_MAX   = 64    # max packets to drain per iteration
        _BATCH_TIMEOUT = 0.05  # seconds to wait for at least one packet

        while True:
            try:
                # Block briefly for the first packet, then drain up to _BATCH_MAX
                # without further blocking.  This keeps latency low while
                # amortising DB writes and print() calls over a batch.
                pkts = []
                try:
                    pkts.append(
                        self.packet_capture.engine_queue.get(timeout=_BATCH_TIMEOUT)
                    )
                except queue.Empty:
                    continue

                while len(pkts) < _BATCH_MAX:
                    try:
                        pkts.append(self.packet_capture.engine_queue.get_nowait())
                    except queue.Empty:
                        break

                all_allowed: list[dict] = []
                for pkt in pkts:
                    all_allowed.extend(self.process_packet(pkt))

                if all_allowed:
                    db_rows = [self._to_db_dict(a) for a in all_allowed]
                    self._save_alerts(db_rows)
                    for a in all_allowed:
                        print(f"[{a['severity']}] {a['type'].upper()} | {a['message']}")

            except KeyboardInterrupt:
                break