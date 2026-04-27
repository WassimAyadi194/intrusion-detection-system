# engine/ids_engine.py
import queue
import sqlite3
import time

from detections.port_scan import PortScanDetector
from detections.connection_tracking import ConnectionTracker
from detections.packets_threshold import PacketThresholdDetector
from detections.alert_gate import AlertGate
from logs.ids_logger import get_logger
from config import DB_NAME, DB_MAX_RETRIES, DB_RETRY_DELAY

log = get_logger(__name__)

# ── Engine batch-drain tuning ─────────────────────────────────────────────────
_BATCH_MAX     = 64    # max packets to drain per iteration
_BATCH_TIMEOUT = 0.05  # seconds to wait for at least one packet

# Severities that are informational only — excluded from both DB writes and
# the UI alert queue. Connection tracking emits INFO on every SYN/FIN packet;
# allowing these through _alert_queue at zero cooldown saturates the UI feed
# and starves the collector queue at wire speed.
_UI_EXCLUDE_SEVERITIES = {"INFO", "LOW"}


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


def _db_write_with_retry(sql: str, rows: list[dict], db_name: str = DB_NAME) -> bool:
    """
    Execute an executemany() with up to DB_MAX_RETRIES retries on failure.

    Returns True if the write succeeded, False if all attempts failed.
    WAL mode is set once at DB initialisation (init_db.py) — not repeated here.
    """
    last_exc: Exception | None = None

    for attempt in range(1 + DB_MAX_RETRIES):
        try:
            conn = sqlite3.connect(db_name, timeout=5)
            cursor = conn.cursor()
            cursor.executemany(sql, rows)
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as exc:
            last_exc = exc
            if attempt < DB_MAX_RETRIES:
                time.sleep(DB_RETRY_DELAY)

    log.error(
        "DB write failed after %d attempts — alerts dropped (n=%d). "
        "Error: %s. First alert: %s",
        1 + DB_MAX_RETRIES,
        len(rows),
        last_exc,
        rows[0] if rows else "N/A",
    )
    return False


# ── Single INSERT used for every alert type ───────────────────────────────────
_ALERT_INSERT_SQL = """
    INSERT INTO alerts
        (host_ip, metric, value, baseline_avg, baseline_std,
         severity, timestamp, description, novelty)
    VALUES
        (:host_ip, :metric, :value, :baseline_avg, :baseline_std,
         :severity, :timestamp, :description, :novelty)
"""


def _to_db_row(alert: dict) -> dict:
    """
    Map a unified alert dict to the alerts table schema.

    Works for all alert types:
    - Rule-based alerts (port_scan, connection, packet_flood): no numeric
      baseline fields — those default to None.
    - Anomaly alerts: carry value/baseline_avg/baseline_std directly.

    The unified key 'src' maps to 'host_ip', 'message' maps to 'description'.
    novelty is populated only for connection alerts; None for everything else.
    """
    return {
        "host_ip":      alert["src"],
        "metric":       alert.get("metric") or alert.get("type", ""),
        "value":        alert.get("value"),
        "baseline_avg": alert.get("baseline_avg"),
        "baseline_std": alert.get("baseline_std"),
        "severity":     alert.get("severity", ""),
        "timestamp":    alert.get("timestamp", int(time.time())),
        "description":  alert.get("message", ""),
        "novelty":      alert.get("novelty"),
    }


class DetectionEngine:
    def __init__(self, packet_capture=None, anomaly_detector=None, alert_queue=None):
        baseline_hosts = _load_baseline_hosts()

        self.port_scan          = PortScanDetector()
        self.connection_tracker = ConnectionTracker(baseline_hosts=baseline_hosts)
        self.packet_threshold   = PacketThresholdDetector()
        self.packet_capture     = packet_capture
        self.anomaly_detector   = anomaly_detector
        self._alert_queue       = alert_queue

        # AlertGate is the single suppression authority for ALL alert types.
        self.alert_gate = AlertGate()

    # ------------------------------------------------------------------
    # Persistence — single path for every alert type
    # ------------------------------------------------------------------

    def _save_alerts(self, alerts: list[dict]) -> None:
        """
        Persist a batch of gated alerts.

        INFO/LOW alerts are never written to the DB — they are connection
        tracking events and low-noise thresholds not worth storing.
        All other severities (MEDIUM, HIGH, CRITICAL) are persisted.
        """
        rows = [
            _to_db_row(a) for a in alerts
            if a.get("severity") not in _UI_EXCLUDE_SEVERITIES
        ]
        if rows:
            _db_write_with_retry(_ALERT_INSERT_SQL, rows)

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

        allowed = [a for a in (self.alert_gate.process(r) for r in raw_alerts) if a]
        return allowed

    # ------------------------------------------------------------------
    # Anomaly window processing (called by LiveMetricsCollector)
    # ------------------------------------------------------------------

    def process_anomaly(self, host_ip: str, **metrics) -> list[dict]:
        """
        Gate and persist anomaly alerts produced by AnomalyDetector.

        Flow:
            1. AnomalyDetector.analyze()  — pure detection, no side effects
            2. AlertGate.process()        — single suppression point
            3. DetectionEngine._save_alerts() — single persistence point
            4. Print approved alerts
        """
        if self.anomaly_detector is None:
            return []

        raw_alerts = self.anomaly_detector.analyze(host_ip, **metrics)
        if not raw_alerts:
            return []

        allowed = [a for a in (self.alert_gate.process(r) for r in raw_alerts) if a]

        if allowed:
            self._save_alerts(allowed)
            for a in allowed:
                print(f"[ANOMALY] {a['severity']} | {a['src']} | {a['message']}")

            if self._alert_queue is not None:
                for a in allowed:
                    if a.get("severity") not in _UI_EXCLUDE_SEVERITIES:
                        self._alert_queue.put_nowait(a)

        return allowed

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self):
        if self.packet_capture is None:
            raise RuntimeError("PacketCapture instance not provided to DetectionEngine.")

        while True:
            try:
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
                    self._save_alerts(all_allowed)
                    for a in all_allowed:
                        msg = f"[{a['severity']}] {a['type'].upper()} | {a['message']}"
                        print(msg.encode(errors="replace").decode())

                    # Only push actionable alerts to the UI queue.
                    # INFO/LOW are connection tracking noise — at zero cooldown
                    # and wire-speed SYN rates they would saturate _alert_queue
                    # and crowd out HIGH/CRITICAL alerts in the feed.
                    if self._alert_queue is not None:
                        for a in all_allowed:
                            if a.get("severity") not in _UI_EXCLUDE_SEVERITIES:
                                self._alert_queue.put_nowait(a)

            except KeyboardInterrupt:
                break