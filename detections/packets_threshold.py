# detections/packets_threshold.py
import time

import config
from baseline.baseline_reader import get_all_baselines
from detections.connection_tracking import ConnectionTracker

# How often (seconds) to refresh the baseline snapshot from the DB.
# Prevents stale data when baselines are trained after the detector starts.
_BASELINE_REFRESH_INTERVAL: float = 120.0


class PacketThresholdDetector:
    """
    Detects packet-flood attacks using a dynamic per-source threshold.

    Thread-safety notes
    -------------------
    - float / int / bool attributes: atomic under CPython's GIL for reads and
      single-assignment writes.
    - sensitivity_penalties (dict): mutate by replacing the whole dict
      atomically — do NOT call dict.update() from outside the engine thread.
    """

    def __init__(self, connection_tracker: ConnectionTracker):
        self.connection_tracker = connection_tracker

        # Tunable parameters (sourced from config, editable at runtime)
        self.k: float                     = config.PACKET_K
        self.min_global_threshold: int    = config.PACKET_MIN_GLOBAL_THRESHOLD
        self.WINDOW: int                  = config.PACKET_WINDOW
        # Dict replacement is the safe mutation pattern for dicts shared with
        # the engine thread.  Copy so the caller cannot accidentally alias the
        # config module's own dict.
        self.sensitivity_penalties: dict  = dict(config.PACKET_SENSITIVITY_PENALTIES)
        self.high_failure_ratio_threshold: float = config.PACKET_HIGH_FAILURE_RATIO_THRESHOLD

        # Internal state
        self.packet_counts: dict[str, dict] = {}
        # Static fallback used when a source IP is absent from the baseline.
        self.THRESHOLD = 3000
        self._last_cleanup: float = 0.0
        self._baselines: dict[str, dict] = get_all_baselines()
        self._baselines_loaded_at: float = time.time()



    # Internal helpers
    
    def _refresh_baselines_if_stale(self, now: float) -> None:
        """Re-fetch baseline snapshot if the refresh interval has elapsed."""
        if now - self._baselines_loaded_at >= _BASELINE_REFRESH_INTERVAL:
            self._baselines = get_all_baselines()
            self._baselines_loaded_at = now



    def _get_threshold(self, src: str, now: float) -> int:
        """
        Return the effective packet-flood threshold for *src*.

            max(round((mean + k * std) * penalty), min_global_threshold)
        """
        host = self._baselines.get(src)
        if host is None:
            # Honour min_global_threshold as the floor even in the no-baseline
            # fallback path, consistent with the dynamic path's behaviour.
            return min(self.THRESHOLD, max(self.min_global_threshold, 1))

        mean    = host.get("avg_packet_count", 0.0) or 0.0
        std     = host.get("std_packet_count", 0.0) or 0.0
        dynamic = (mean + (self.k * std)) * self.connection_tracker.compute_penalty_multiplier(
            src, now, self.sensitivity_penalties, self._baselines, self.high_failure_ratio_threshold
        )
        # Clamp: never go below min_global_threshold, never go below 1
        return max(int(round(dynamic)), max(self.min_global_threshold, 1))

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
            # Window expired — start fresh.  Current packet opens the new window.
            self.packet_counts[src] = {"count": 1, "start": now}
        else:
            entry["count"] += 1
            threshold = self._get_threshold(src, now)

            if entry["count"] >= threshold:
                msg = f"PACKET FLOOD DETECTED from {src}"
                alerts.append({
                    "src":       src,
                    "type":      "packet_flood",
                    # Stable string key — allows AlertGate to deduplicate flood
                    # alerts from the same source via its DEFAULT_COOLDOWN.
                    "metric":    "packet_flood",
                    "value":     entry["count"],
                    "severity":  "MEDIUM",
                    "message":   msg,
                    "timestamp": int(now),
                })
                # Reset the window after threshold is crossed.
                del self.packet_counts[src]

        if now - self._last_cleanup >= self.WINDOW:
            self.cleanup(now)
            self._last_cleanup = now

        return alerts if alerts else None

    def cleanup(self, now: float) -> None:
        for src in list(self.packet_counts.keys()):
            if now - self.packet_counts[src]["start"] > self.WINDOW:
                del self.packet_counts[src]