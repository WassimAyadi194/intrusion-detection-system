# engine/ids_engine.py
import queue
import sqlite3
import time

from detections.port_scan import PortScanDetector
from detections.connection_tracking import ConnectionTracker
from detections.packets_threshold import PacketThresholdDetector
from detections.alert_gate import AlertGate
from logs.ids_logger import get_logger
from config import DB_NAME, DB_MAX_RETRIES, DB_RETRY_DELAY, WINDOW_SIZE

log = get_logger(__name__)

_BATCH_MAX     = 64    # max packets to drain per iteration
_BATCH_TIMEOUT = 0.05  # seconds to wait for at least one packet

# Severities that are informational only — excluded from both DB writes and the UI alert queue.
_UI_EXCLUDE_SEVERITIES = {"INFO", "LOW"}

# Window (seconds) used by the "Alerts (60 s)" KPI tile.
_KPI_ALERT_WINDOW, _SNAPSHOT_ALERT_WINDOW = 60, 60

_ANOMALY_LEVEL_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
    "NONE":     "NONE",
}
 

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


# Single INSERT used for every alert type
_ALERT_INSERT_SQL = """
    INSERT INTO alerts
        (host_ip, metric, value, baseline_avg, baseline_std,
         severity, timestamp, description, novelty)
    VALUES
        (:host_ip, :metric, :value, :baseline_avg, :baseline_std,
         :severity, :timestamp, :description, :novelty)
"""


def _to_db_row(alert: dict) -> dict:
    # Map a unified alert dict to the alerts table schema.
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
    def __init__(self, packet_capture=None, anomaly_detector=None, alert_queue=None, collector=None):
        baseline_hosts = _load_baseline_hosts()

        self.connection_tracker = ConnectionTracker(baseline_hosts=baseline_hosts)
        self.port_scan          = PortScanDetector(self.connection_tracker)
        self.packet_threshold   = PacketThresholdDetector(self.connection_tracker)
        self.packet_capture     = packet_capture
        self.anomaly_detector   = anomaly_detector
        self._alert_queue       = alert_queue
        self.collector          = collector

        # AlertGate is the single suppression authority for ALL alert types.
        self.alert_gate = AlertGate()

    @property
    def capture_state(self) -> str:
        """
        Derive capture state from PacketCapture's stop event.
        Returns one of: "RUNNING", "STOPPED", "N/A"
        """
        if self.packet_capture is None:
            return "N/A"
        return "STOPPED" if self.packet_capture._stop_event.is_set() else "RUNNING"

    def kpi_snapshot(self) -> dict:
        """
        Return a lightweight dict of all four KPI values, safe to call from
        any thread (Qt timer thread included).
        """
        # Alerts in the last 60 s — reads only the deque, O(n) but tiny.
        alerts_60s = self.alert_gate.count_since(time.time() - _KPI_ALERT_WINDOW)

        # Unique source IPs currently tracked in the connection table.
        # The dict is written from the engine thread; reading it here is
        # safe under CPython's GIL (dict iteration is atomic enough for a
        # best-effort KPI read).
        active_hosts = len({k[0] for k in self.connection_tracker.connections})

        # Queue depths — qsize() is always thread-safe on queue.Queue.
        if self.packet_capture is not None:
            engine_q    = self.packet_capture.engine_queue.qsize()
            collector_q = self.packet_capture.collector_queue.qsize()
        else:
            engine_q    = 0
            collector_q = 0

        return {
            "alerts_60s":    alerts_60s,
            "active_hosts":  active_hosts,
            "engine_q":      engine_q,
            "collector_q":   collector_q,
            "capture_state": self.capture_state,
        }

    def host_metrics_snapshot(self) -> dict[str, dict]:
    
        now   = time.time()
        since = now - _SNAPSHOT_ALERT_WINDOW
    
        current: dict[str, dict] = {}
        if self.collector is not None:
            for host_ip, m in self.collector.host_data.items():
                current[host_ip] = {
                    "pkt_current":                 m["packet_count"],
                    "syn_count_current":           m["syn_count"],
                    "unique_destinations_current": len(m["unique_destinations"]),
                    "unique_ports_current":        len(m["unique_ports"]),
                }
    
        
        last_window: dict[str, dict] = (
            self.collector._last_window if self.collector is not None else {}
        )
    
        conn_counts: dict[str, int] = {}
        for key in self.connection_tracker.connections:
            src = key[0]
            conn_counts[src] = conn_counts.get(src, 0) + 1
    
        # ── 4. Novelty — most recent classification per src ───────────────────────
        # ConnectionTracker._classify_novelty() is a pure function of
        # _syn_counts and baseline_hosts; calling it here is side-effect free.
        # We only call it for hosts that appear in our working set so we avoid
        # touching every IP in _syn_counts unnecessarily.
    
        # ── 5. Build the working host set ─────────────────────────────────────────
        all_hosts: set[str] = (
            set(current.keys())
            | set(last_window.keys())
            | set(conn_counts.keys())
        )
    
        result: dict[str, dict] = {}
    
        for host_ip in all_hosts:
            cur = current.get(host_ip, {})
            lw  = last_window.get(host_ip, {})
    
            pkt_last = lw.get("packet_count", 0)
            pkt_rate = pkt_last / WINDOW_SIZE if pkt_last else 0.0
    
            # Anomaly level — delegated entirely to AlertGate (thread-safe RLock)
            anomaly_level = self.alert_gate.worst_severity_since(host_ip, since)
    
            # Novelty — pure function, no side effects
            novelty = self.connection_tracker._classify_novelty(host_ip, now)
    
            anomaly_count = self.alert_gate.count_host_since(host_ip, now - 2)

            result[host_ip] = {
                "pkt_current":                 cur.get("pkt_current", 0),
                "pkt_last":                    pkt_last,
                "pkt_rate":                    round(pkt_rate, 2),
                "active_connections":          conn_counts.get(host_ip, 0),
                "syn_count_current":           cur.get("syn_count_current", 0),
                "anomaly_level":               anomaly_level,
                "anomaly_count":               anomaly_count,
                "unique_destinations_current": cur.get("unique_destinations_current", 0),
                "unique_ports_current":        cur.get("unique_ports_current", 0),
                "novelty":                     novelty,
            }
    
        return result 

    def _save_alerts(self, alerts: list[dict]) -> None:
        #Persist a batch of gated alerts.
        rows = [
            _to_db_row(a) for a in alerts
            if a.get("severity") not in _UI_EXCLUDE_SEVERITIES
        ]
        if rows:
            _db_write_with_retry(_ALERT_INSERT_SQL, rows)

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

    def process_anomaly(self, host_ip: str, **metrics):
        # Gate and persist anomaly alerts produced by AnomalyDetector.
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

    # Main loop
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