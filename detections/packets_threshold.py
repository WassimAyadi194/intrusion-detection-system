# detections/packets_threshold.py
import time

from baseline.baseline_reader import get_all_baselines
from detections.connection_tracking import ConnectionTracker

# Multiplier for the standard deviation term in the dynamic threshold formula.
# At 5σ a normal-distribution false-positive rate is ~0.00006%, safely above
# any tab-refresh / streaming burst.
_K: float = 2.0

# Absolute lower bound — prevents the threshold from being too permissive for
# hosts whose mean + k*std is unrealistically low.
_MIN_GLOBAL_THRESHOLD: int = 1000

# Cooldown (seconds) per source IP after a flood alert fires.
_ALERT_COOLDOWN: float = 10.0

# How often (seconds) to refresh the baseline snapshot from the DB.
# Prevents stale data when baselines are trained after the detector starts.
_BASELINE_REFRESH_INTERVAL: float = 120.0

# Multipliers applied to dynamic thresholds based on connection tracker signals.
# Set a value to 1.0 to disable that penalty.
SENSITIVITY_PENALTIES: dict[str, float] = {
    "novelty_new":        0.8,   # 20% stricter for hosts with no baseline history
    "high_failure_ratio": 0.8,   # 20% stricter for hosts with high RST/timeout rate
}

# Failed-connection ratio above which the high_failure_ratio penalty is applied.
HIGH_FAILURE_RATIO_THRESHOLD: float = 0.6


class PacketThresholdDetector:
    def __init__(self, connection_tracker: ConnectionTracker):
        self.connection_tracker = connection_tracker
        self.packet_counts: dict[str, dict] = {}
        self.WINDOW = 10
        # Static fallback used when a source IP is absent from the baseline.
        self.THRESHOLD = 3000
        self._last_cleanup: float = 0.0
        self._baselines: dict[str, dict] = get_all_baselines()
        self._baselines_loaded_at: float = time.time()
        # Tracks the last flood-alert time per source IP for cooldown enforcement.
        self._last_alert_ts: dict[str, float] = {}

    def _refresh_baselines_if_stale(self, now: float) -> None:
        """Re-fetch baseline snapshot if the refresh interval has elapsed."""
        if now - self._baselines_loaded_at >= _BASELINE_REFRESH_INTERVAL:
            self._baselines = get_all_baselines()
            self._baselines_loaded_at = now

    def _penalty_multiplier(self, src: str, now: float) -> float:
        """
        Compute the combined sensitivity-penalty multiplier for *src*.

        Fetches host stats from the ConnectionTracker and applies
        SENSITIVITY_PENALTIES multiplicatively.  A value < 1.0 tightens
        (lowers) the dynamic threshold, making detection more aggressive.

        The novelty_new penalty is applied only when the host is both
        classified as "new" by the ConnectionTracker AND has no entry in the
        baseline DB.  A host that has a full baseline entry (mean, std) but
        happens not to be in baseline_hosts would otherwise be penalised on
        top of an already well-tuned dynamic threshold — a double-penalty that
        produces thresholds that are too aggressive.
        """
        stats = self.connection_tracker.get_host_stats(src, now)
        multiplier = 1.0

        # Only penalise truly unknown hosts — those with neither a baseline
        # DB entry nor enough observed traffic to be classified as recurring.
        if stats["novelty"] == "new" and self._baselines.get(src) is None:
            multiplier *= SENSITIVITY_PENALTIES["novelty_new"]

        if stats["failed_connection_ratio"] > HIGH_FAILURE_RATIO_THRESHOLD:
            multiplier *= SENSITIVITY_PENALTIES["high_failure_ratio"]

        return multiplier

    def analyze_packet(self, pkt) -> list[dict] | None:
        if "IP" not in pkt:
            return None

        src = pkt["IP"].src
        now = time.time()

        self._refresh_baselines_if_stale(now)

        if src not in self.packet_counts:
            self.packet_counts[src] = {"count": 0, "start": now}

        entry = self.packet_counts[src]
        alerts = []

        if now - entry["start"] > self.WINDOW:
            # Window expired — start fresh. Current packet opens the new window.
            self.packet_counts[src] = {"count": 1, "start": now}
        else:
            entry["count"] += 1
            threshold = self._get_threshold(src, now)

            if entry["count"] >= threshold:
                last_alert = self._last_alert_ts.get(src, 0.0)
                if now - last_alert >= _ALERT_COOLDOWN:
                    self._last_alert_ts[src] = now
                    alerts.append({
                        "src":       src,
                        "type":      "packet_flood",
                        "metric":    entry["count"],
                        "severity":  "MEDIUM",
                        "message":   f"PACKET FLOOD DETECTED from {src}",
                        "timestamp": int(now),
                    })
                # Reset the window only after threshold is crossed (alert or suppressed).
                # Previously this del was OUTSIDE the `if entry["count"] >= threshold`
                # block, so it ran on every single packet once the count hit threshold,
                # resetting to zero and immediately climbing back up — causing repeated
                # fires within one burst even when the dynamic threshold was 10 000+.
                del self.packet_counts[src]

        if now - self._last_cleanup >= self.WINDOW:
            self.cleanup(now)
            self._last_cleanup = now

        return alerts if alerts else None

    def _get_threshold(self, src: str, now: float) -> int:
        """
        Return the effective packet-flood threshold for *src*.

            max(round((mean + K * std) * penalty), _MIN_GLOBAL_THRESHOLD)

        The penalty multiplier is sourced from the ConnectionTracker to apply
        stricter thresholds for new or high-failure-rate hosts.
        """
        host = self._baselines.get(src)
        if host is None:
            return self.THRESHOLD

        mean    = host.get("avg_packet_count", 0.0) or 0.0
        std     = host.get("std_packet_count", 0.0) or 0.0
        dynamic = (mean + (_K * std)) * self._penalty_multiplier(src, now)
        return max(int(round(dynamic)), _MIN_GLOBAL_THRESHOLD)

    def cleanup(self, now: float) -> None:
        for src in list(self.packet_counts.keys()):
            if now - self.packet_counts[src]["start"] > self.WINDOW:
                del self.packet_counts[src]

        # Evict stale cooldown entries to prevent unbounded growth.
        for src in list(self._last_alert_ts.keys()):
            if now - self._last_alert_ts[src] > _ALERT_COOLDOWN:
                del self._last_alert_ts[src]