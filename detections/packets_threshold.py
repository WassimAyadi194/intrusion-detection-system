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

    All tunable parameters are stored as *instance* attributes so that the
    frontend settings panel can mutate them at runtime (e.g. self.k = 3.0)
    without restarting the engine.  The values are initialised from config.py
    (which itself loads from ids_settings.json at startup).

    Thread-safety notes
    -------------------
    - float / int / bool attributes: atomic under CPython's GIL for reads and
      single-assignment writes.
    - sensitivity_penalties (dict): mutate by replacing the whole dict
      atomically — do NOT call dict.update() from outside the engine thread.
    """

    def __init__(self, connection_tracker: ConnectionTracker):
        self.connection_tracker = connection_tracker

        # ── Tunable parameters (sourced from config, editable at runtime) ──────
        self.k: float                     = config.PACKET_K
        self.min_global_threshold: int    = config.PACKET_MIN_GLOBAL_THRESHOLD
        self.WINDOW: int                  = config.PACKET_WINDOW
        # Dict replacement is the safe mutation pattern for dicts shared with
        # the engine thread.  Copy so the caller cannot accidentally alias the
        # config module's own dict.
        self.sensitivity_penalties: dict  = dict(config.PACKET_SENSITIVITY_PENALTIES)
        self.high_failure_ratio_threshold: float = config.PACKET_HIGH_FAILURE_RATIO_THRESHOLD

        # ── Internal state ────────────────────────────────────────────────────
        self.packet_counts: dict[str, dict] = {}
        # Static fallback used when a source IP is absent from the baseline.
        self.THRESHOLD = 3000
        self._last_cleanup: float = 0.0
        self._baselines: dict[str, dict] = get_all_baselines()
        self._baselines_loaded_at: float = time.time()
        # Tracks the last flood-alert time per source IP for cooldown enforcement.
        self._last_alert_ts: dict[str, float] = {}
        # Cooldown (seconds) per source IP after a flood alert fires.
        self._alert_cooldown: float = 10.0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _refresh_baselines_if_stale(self, now: float) -> None:
        """Re-fetch baseline snapshot if the refresh interval has elapsed."""
        if now - self._baselines_loaded_at >= _BASELINE_REFRESH_INTERVAL:
            self._baselines = get_all_baselines()
            self._baselines_loaded_at = now

    def _penalty_multiplier(self, src: str, now: float) -> float:
        """
        Compute the combined sensitivity-penalty multiplier for *src*.

        Fetches host stats from the ConnectionTracker and applies
        self.sensitivity_penalties multiplicatively.  A value < 1.0 tightens
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

        # Snapshot the dict reference once to avoid TOCTOU if the settings
        # panel replaces it between the two reads below.
        penalties = self.sensitivity_penalties

        # Only penalise truly unknown hosts — those with neither a baseline
        # DB entry nor enough observed traffic to be classified as recurring.
        if stats["novelty"] == "new" and self._baselines.get(src) is None:
            multiplier *= penalties.get("novelty_new", 1.0)

        if stats["failed_connection_ratio"] > self.high_failure_ratio_threshold:
            multiplier *= penalties.get("high_failure_ratio", 1.0)

        return multiplier

    def _get_threshold(self, src: str, now: float) -> int:
        """
        Return the effective packet-flood threshold for *src*.

            max(round((mean + k * std) * penalty), min_global_threshold)

        The penalty multiplier is sourced from the ConnectionTracker to apply
        stricter thresholds for new or high-failure-rate hosts.

        Guard: if the computed dynamic value is unrealistically low (< 1),
        fall back to the static THRESHOLD to prevent divide-by-zero-style
        runaway detection after misconfiguration.
        """
        host = self._baselines.get(src)
        if host is None:
            return self.THRESHOLD

        mean    = host.get("avg_packet_count", 0.0) or 0.0
        std     = host.get("std_packet_count", 0.0) or 0.0
        dynamic = (mean + (self.k * std)) * self._penalty_multiplier(src, now)
        # Clamp: never go below min_global_threshold, never go below 1
        return max(int(round(dynamic)), max(self.min_global_threshold, 1))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

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
                last_alert = self._last_alert_ts.get(src, 0.0)
                if now - last_alert >= self._alert_cooldown:
                    self._last_alert_ts[src] = now
                    msg = f"PACKET FLOOD DETECTED from {src}"
                    alerts.append({
                        "src":       src,
                        "type":      "packet_flood",
                        "metric":    entry["count"],
                        "severity":  "MEDIUM",
                        "message":   msg,
                        "timestamp": int(now),
                    })
                # Reset the window only after threshold is crossed (alert or suppressed).
                del self.packet_counts[src]

        if now - self._last_cleanup >= self.WINDOW:
            self.cleanup(now)
            self._last_cleanup = now

        return alerts if alerts else None

    def cleanup(self, now: float) -> None:
        for src in list(self.packet_counts.keys()):
            if now - self.packet_counts[src]["start"] > self.WINDOW:
                del self.packet_counts[src]

        # Evict stale cooldown entries to prevent unbounded growth.
        for src in list(self._last_alert_ts.keys()):
            if now - self._last_alert_ts[src] > self._alert_cooldown:
                del self._last_alert_ts[src]