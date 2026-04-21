# baseline/anomaly_detector.py
import sqlite3
import time

DB_NAME = "ids.db"

# How many standard deviations from the mean triggers an alert.
# 2.5 catches clear outliers while avoiding excessive false positives.
Z_THRESHOLD = 2.5

# If std is 0 (perfectly stable baseline), use this floor so a nonzero
# value still triggers an alert rather than dividing by zero.
STD_FLOOR = 0.1

SEVERITY_LEVELS = [
    (4.0, "CRITICAL"),
    (3.0, "HIGH"),
    (2.5, "MEDIUM"),
]


def _severity(z_score: float) -> str:
    for threshold, label in SEVERITY_LEVELS:
        if abs(z_score) >= threshold:
            return label
    return "LOW"


class AnomalyDetector:
    def __init__(self):
        self._baseline_cache: dict[str, dict] = {}
        self._cache_ttl = 300  # seconds before re-reading from DB
        self._cache_ts: dict[str, float] = {}

    def _load_baseline(self, host_ip: str) -> dict | None:
        """
        Returns the baseline row for host_ip, using a short-lived cache
        so we don't hit the DB on every window flush.
        """
        now = time.time()
        if (
            host_ip in self._baseline_cache
            and now - self._cache_ts.get(host_ip, 0) < self._cache_ttl
        ):
            return self._baseline_cache[host_ip]

        conn = sqlite3.connect(DB_NAME, timeout=5)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM baseline WHERE host_ip = ?", (host_ip,)
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            self._baseline_cache[host_ip] = dict(row)
            self._cache_ts[host_ip] = now
            return self._baseline_cache[host_ip]

        return None

    # Human-readable labels and description templates per metric.
    # Each entry: (label, description_fn)
    # description_fn receives (host_ip, value, avg) and returns a plain-English string.
    _METRIC_DESCRIPTIONS = {
        "syn_count": (
            "SYN packets",
            lambda host, val, avg: (
                f"Abnormal connection rate from {host} — "
                f"{int(val)} SYN packets in 10s (normal: ~{avg:.0f})"
            ),
        ),
        "unique_ports": (
            "distinct ports",
            lambda host, val, avg: (
                f"Port scanning behavior from {host} — "
                f"contacted {int(val)} distinct ports in 10s (normal: ~{avg:.0f})"
            ),
        ),
        "unique_destinations": (
            "distinct destinations",
            lambda host, val, avg: (
                f"Unusual outreach from {host} — "
                f"contacted {int(val)} distinct hosts in 10s (normal: ~{avg:.0f})"
            ),
        ),
        "packet_count": (
            "total packets",
            lambda host, val, avg: (
                f"Abnormal packet volume from {host} — "
                f"{int(val)} packets in 10s (normal: ~{avg:.0f})"
            ),
        ),
    }

    def _check_metric(
        self,
        host_ip: str,
        metric: str,
        value: float,
        avg: float,
        std: float,
        timestamp: int,
    ) -> dict | None:
        """
        Computes the Z-score for one metric. Returns a raw alert dict if the
        score exceeds Z_THRESHOLD, otherwise None.

        The returned dict uses the unified schema expected by AlertGate:
            src, type, metric, severity, message, timestamp
        It also carries the extra DB fields (value, baseline_avg, baseline_std)
        so save_alerts() can persist them without losing information.
        novelty is always None for anomaly alerts — the column is nullable.
        """
        effective_std = max(std, STD_FLOOR)
        z = (value - avg) / effective_std

        if abs(z) < Z_THRESHOLD:
            return None

        severity = _severity(z)

        _, description_fn = self._METRIC_DESCRIPTIONS.get(
            metric,
            ("unknown", lambda host, val, avg: f"Anomalous {metric} from {host}: {int(val)} (normal: ~{avg:.0f})")
        )

        description = description_fn(host_ip, value, avg)

        return {
            # Unified AlertGate fields
            "src":          host_ip,
            "type":         "anomaly",
            "metric":       metric,
            "severity":     severity,
            "message":      description,
            "timestamp":    timestamp,
            # Extra fields kept for DB persistence (save_alerts uses these)
            "host_ip":      host_ip,
            "value":        round(value, 2),
            "baseline_avg": round(avg, 2),
            "baseline_std": round(std, 2),
            "description":  description,
            # novelty is not applicable to anomaly alerts; stored as NULL
            "novelty":      None,
        }
    
# In analyze(), update the signature and the checks list:

    def analyze(
        self,
        host_ip: str,
        syn_count: int,
        unique_ports: int,
        unique_destinations: int,
        packet_count: int = 0,          # ← NEW, default=0 keeps old callers safe
    ) -> list[dict]:
        baseline = self._load_baseline(host_ip)
        if baseline is None:
            return []

        timestamp = int(time.time())
        alerts = []

        checks = [
            ("syn_count",           syn_count,           baseline["avg_syn"],                  baseline["std_syn"]),
            ("unique_ports",        unique_ports,        baseline["avg_unique_ports"],          baseline["std_unique_ports"]),
            ("unique_destinations", unique_destinations, baseline["avg_unique_destinations"],   baseline["std_unique_destinations"]),
            ("packet_count",        packet_count,        baseline.get("avg_packet_count", 0),   baseline.get("std_packet_count", 0)),  # ← NEW
        ]

        for metric, value, avg, std in checks:
            alert = self._check_metric(host_ip, metric, value, avg, std, timestamp)
            if alert:
                alerts.append(alert)

        return alerts

    def save_alerts(self, alerts: list[dict]):
        """Write a batch of alert dicts to the alerts table."""
        if not alerts:
            return

        conn = sqlite3.connect(DB_NAME, timeout=5)
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