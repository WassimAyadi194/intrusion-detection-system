# baseline/anomaly_detector.py
import sqlite3
import time

import config
from logs.ids_logger import get_logger
from config import DB_NAME

log = get_logger(__name__)

# How many standard deviations from the mean triggers an alert.
Z_THRESHOLD = 1.5

SEVERITY_LEVELS = [
    (4.0, "CRITICAL"),
    (3.0, "HIGH"),
    (2.5, "MEDIUM"),  
    (1.5, "LOW"),
]

# Cooldown (seconds) per (host_ip, metric) after an alert fires.
# Prevents the same burst straddling two 10-second windows from double-alerting.
_ALERT_COOLDOWN = 30  # seconds


def _severity(z_score: float) -> str:
    for threshold, label in SEVERITY_LEVELS:
        if abs(z_score) >= threshold:
            return label
    return "LOW"


class AnomalyDetector:
    
    def __init__(self):
        # ── Tunable parameters (sourced from config, editable at runtime) ──────
        self.std_floor: float              = config.ANOMALY_STD_FLOOR
        self.min_baseline_samples: int     = config.ANOMALY_MIN_BASELINE_SAMPLES
        # Dict replacement is the safe mutation pattern for dicts shared with
        # the engine thread.  Copy so the caller cannot alias the config dict.
        self.min_deltas: dict[str, float]  = dict(config.ANOMALY_MIN_DELTAS)

        # ── Internal state ────────────────────────────────────────────────────
        self._baseline_cache: dict[str, dict] = {}
        self._cache_ttl = 300  # seconds before re-reading from DB
        self._cache_ts: dict[str, float] = {}
        # Tracks the last alert time per (host_ip, metric) for cooldown enforcement.
        self._last_alert_ts: dict[tuple[str, str], float] = {}
        self._check_baseline_populated()

    @staticmethod
    def _check_baseline_populated() -> None:
        """Warn once at startup if the baseline table is completely empty."""
        try:
            conn = sqlite3.connect(DB_NAME, timeout=5)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM baseline")
            count = cursor.fetchone()[0]
            conn.close()
            if count == 0:
                log.warning(
                    "Baseline table is empty — anomaly detection will be inactive "
                    "until baseline_trainer.py has been run"
                )
        except sqlite3.Error:
            pass  # DB may not exist yet at startup; not an error worth surfacing here

    def _load_baseline(self, host_ip: str) -> dict | None:
        """
        Returns the baseline row for host_ip, using a short-lived cache
        so we don't hit the DB on every window flush.
        Expired entries are evicted on access to prevent unbounded memory growth.
        """
        now = time.time()
        if host_ip in self._baseline_cache:
            if now - self._cache_ts[host_ip] < self._cache_ttl:
                return self._baseline_cache[host_ip]
            # TTL expired — evict so we re-read a potentially updated baseline
            del self._baseline_cache[host_ip]
            del self._cache_ts[host_ip]

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

        # No baseline entry for this host — normal for most IPs. Silent return.
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
        
        effective_std_floor = max(self.std_floor, 1e-6)
        effective_std = max(std, effective_std_floor)
        z = (value - avg) / effective_std

        # Only alert on spikes (positive Z-score), not drops.
        if z < Z_THRESHOLD:
            return None

        # Absolute-delta guard — snapshot min_deltas once to be safe.
        min_deltas = self.min_deltas
        min_delta = min_deltas.get(metric, 10.0)
        if (value - avg) < min_delta:
            return None

        # Cooldown guard — suppress repeated alerts for the same (host, metric).
        cooldown_key = (host_ip, metric)
        now = float(timestamp)
        last = self._last_alert_ts.get(cooldown_key, 0.0)
        if now - last < _ALERT_COOLDOWN:
            return None
        self._last_alert_ts[cooldown_key] = now

        severity = _severity(z)

        _, description_fn = self._METRIC_DESCRIPTIONS.get(
            metric,
            ("unknown", lambda host, val, avg: f"Anomalous {metric} from {host}: {int(val)} (normal: ~{avg:.0f})")
        )

        return {
            # Unified AlertGate / engine schema
            "src":          host_ip,
            "type":         "anomaly",
            "metric":       metric,
            "severity":     severity,
            "message":      description_fn(host_ip, value, avg),
            "timestamp":    timestamp,
            # Numeric baseline context — used by _save_alerts() in ids_engine
            "value":        round(value, 2),
            "baseline_avg": round(avg, 2),
            "baseline_std": round(std, 2),
            # novelty is not applicable to anomaly alerts; stored as NULL
            "novelty":      None,
        }

    def analyze(
        self,
        host_ip: str,
        syn_count: int,
        unique_ports: int,
        unique_destinations: int,
        packet_count: int = 0,
    ) -> list[dict]:
        baseline = self._load_baseline(host_ip)
        if baseline is None:
            return []

        # Reject baselines built on too few observations. A host seen only a
        # handful of times during training will have near-zero means/stds, so
        # any normal burst produces enormous Z-scores and fires false positives.
        if baseline.get("sample_count", 0) < self.min_baseline_samples:
            return []

        timestamp = int(time.time())
        alerts = []

        checks = [
            ("syn_count",           syn_count,           baseline["avg_syn"],                  baseline["std_syn"]),
            ("unique_ports",        unique_ports,        baseline["avg_unique_ports"],          baseline["std_unique_ports"]),
            ("unique_destinations", unique_destinations, baseline["avg_unique_destinations"],   baseline["std_unique_destinations"]),
            ("packet_count",        packet_count,        baseline.get("avg_packet_count", 0),   baseline.get("std_packet_count", 0)),
        ]

        for metric, value, avg, std in checks:
            alert = self._check_metric(host_ip, metric, value, avg, std, timestamp)
            if alert:
                alerts.append(alert)

        return alerts