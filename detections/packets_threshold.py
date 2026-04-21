# detections/packets_threshold.py
import time
import sqlite3

DB_NAME = "ids.db"

# ── Existing detector (unchanged) ────────────────────────────────────────────

class PacketThresholdDetector:
    def __init__(self):
        self.packet_counts = {}
        self.WINDOW = 10
        self.THRESHOLD = 3000

    def analyze_packet(self, pkt) -> list[dict] | None:
        if "IP" not in pkt:
            return None

        src = pkt["IP"].src
        now = time.time()

        if src not in self.packet_counts:
            self.packet_counts[src] = {"count": 0, "start": now}

        entry = self.packet_counts[src]
        entry["count"] += 1

        alerts = []

        if now - entry["start"] <= self.WINDOW:
            if entry["count"] >= self.THRESHOLD:
                alerts.append({
                    "src":       src,
                    "type":      "packet_flood",
                    "metric":    None,
                    "severity":  "MEDIUM",
                    "message":   f"PACKET FLOOD DETECTED from {src}",
                    "timestamp": int(now),
                })
                del self.packet_counts[src]
        else:
            self.packet_counts[src] = {"count": 1, "start": now}

        self.cleanup(now)

        return alerts if alerts else None

    def cleanup(self, now):
        for src in list(self.packet_counts.keys()):
            if now - self.packet_counts[src]["start"] > self.WINDOW:
                del self.packet_counts[src]


# ── NEW: baseline-driven flood detector (called per window flush) ─────────────

STD_FLOOR    = 0.1   # matches anomaly_detector.py
Z_THRESHOLD  = 3.0   # stricter than anomaly metrics — flood needs a clear signal

SEVERITY_LEVELS = [
    (5.0, "CRITICAL"),
    (4.0, "HIGH"),
    (3.0, "MEDIUM"),
]


def _severity(z: float) -> str:
    for threshold, label in SEVERITY_LEVELS:
        if abs(z) >= threshold:
            return label
    return "LOW"


class PacketBaselineDetector:
    """
    Window-level packet flood detector.  Called once per 10-second flush
    (not per packet) by the engine alongside AnomalyDetector.

    Uses the baseline avg/std_packet_count trained by baseline_trainer.py
    to compute a Z-score rather than a fixed threshold.
    """

    def __init__(self):
        self._cache: dict[str, dict] = {}
        self._cache_ts: dict[str, float] = {}
        self._cache_ttl = 300  # seconds — matches AnomalyDetector

    def _load_baseline(self, host_ip: str) -> dict | None:
        now = time.time()
        if (
            host_ip in self._cache
            and now - self._cache_ts.get(host_ip, 0) < self._cache_ttl
        ):
            return self._cache[host_ip]

        conn = sqlite3.connect(DB_NAME, timeout=5)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT avg_packet_count, std_packet_count FROM baseline WHERE host_ip = ?",
            (host_ip,),
        )
        row = cursor.fetchone()
        conn.close()

        if row and row["avg_packet_count"] is not None:
            entry = dict(row)
            self._cache[host_ip] = entry
            self._cache_ts[host_ip] = now
            return entry

        return None

    def analyze(self, host_ip: str, packet_count: int, timestamp: int) -> list[dict]:
        """
        Returns a list with one alert dict if packet_count is anomalous
        relative to the trained baseline, otherwise an empty list.

        Alert format is identical to PacketThresholdDetector so AlertGate
        and save_alerts() need no changes.
        """
        baseline = self._load_baseline(host_ip)
        if baseline is None:
            return []

        avg = baseline["avg_packet_count"]
        std = baseline["std_packet_count"] or 0.0
        effective_std = max(std, STD_FLOOR)
        z = (packet_count - avg) / effective_std

        if abs(z) < Z_THRESHOLD:
            return []

        severity = _severity(z)

        return [{
            # Unified AlertGate fields
            "src":          host_ip,
            "type":         "packet_flood",
            "metric":       "packet_count",
            "severity":     severity,
            "message": (
                f"Abnormal packet volume from {host_ip} — "
                f"{packet_count} packets in 10s (normal: ~{avg:.0f})"
            ),
            "timestamp":    timestamp,
            # DB persistence fields (matches save_alerts schema)
            "host_ip":      host_ip,
            "value":        round(float(packet_count), 2),
            "baseline_avg": round(avg, 2),
            "baseline_std": round(std, 2),
            "description": (
                f"Abnormal packet volume from {host_ip} — "
                f"{packet_count} packets in 10s (normal: ~{avg:.0f})"
            ),
            "novelty":      None,
        }]