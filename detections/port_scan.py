# detections/port_scan.py
import time

import config
from baseline.baseline_reader import get_all_baselines
from detections.connection_tracking import ConnectionTracker

CLEANUP_INTERVAL = 10  # seconds between scan-table cleanup passes

# How often (seconds) to refresh the baseline snapshot from the DB.
_BASELINE_REFRESH_INTERVAL: float = 120.0

# Hard-tripwire constants (not user-tunable — operational safety rails).
HARD_TRIP_MIN_SYNS: int   = 10   # minimum SYNs before hard tripwire can fire
HARD_TRIP_COOLDOWN: float = 30.0 # cooldown before the hard tripwire can fire again


class PortScanDetector:

    def __init__(self, connection_tracker: ConnectionTracker):
        self.connection_tracker = connection_tracker

        # ── Tunable parameters (sourced from config, editable at runtime) ──────
        self.k: float                           = config.PORT_SCAN_K
        self.min_port_scan_limit: int           = config.PORT_SCAN_MIN_PORT_SCAN_LIMIT
        self.min_host_scan_limit: int           = config.PORT_SCAN_MIN_HOST_SCAN_LIMIT
        # Dict replacement is the safe mutation pattern for dicts shared with
        # the engine thread.  Copy so the caller cannot alias the config dict.
        self.sensitivity_penalties: dict        = dict(config.PORT_SCAN_SENSITIVITY_PENALTIES)
        self.high_failure_ratio_threshold: float = config.PORT_SCAN_HIGH_FAILURE_RATIO_THRESHOLD
        # Set replacement is the safe pattern for sets.
        self.static_threshold_ports: set        = set(config.PORT_SCAN_STATIC_THRESHOLD_PORTS)

        # ── Scan-state tables ─────────────────────────────────────────────────
        self.vertical_scan:   dict = {}
        self.horizontal_scan: dict = {}
        self.SCAN_WINDOW: int = 30

        # Static fallbacks used when a source IP is absent from the baseline.
        self.PORT_THRESHOLD = 8
        self.HOST_THRESHOLD = 10

        self._last_cleanup: float = 0.0
        self._baselines: dict[str, dict] = get_all_baselines()
        self._baselines_loaded_at: float = time.time()
        # Tracks the last hard-tripwire alert time per source IP.
        self._last_hard_trip_ts: dict[str, float] = {}

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

    def _get_vertical_threshold(self, src: str, now: float) -> int:
        
        host = self._baselines.get(src)
        if host is None:
            return self.PORT_THRESHOLD

        mean    = host.get("avg_unique_ports", 0.0) or 0.0
        std     = host.get("std_unique_ports", 0.0) or 0.0
        dynamic = (mean + (self.k * std)) * self._penalty_multiplier(src, now)
        return max(int(round(dynamic)), max(self.min_port_scan_limit, 1))

    def _get_horizontal_threshold(self, src: str, now: float, apply_penalty: bool = True) -> int:
        
        host = self._baselines.get(src)
        if host is None:
            return self.HOST_THRESHOLD

        mean    = host.get("avg_unique_destinations", 0.0) or 0.0
        std     = host.get("std_unique_destinations", 0.0) or 0.0
        penalty = self._penalty_multiplier(src, now) if apply_penalty else 1.0
        dynamic = (mean + (self.k * std)) * penalty
        return max(int(round(dynamic)), max(self.min_host_scan_limit, 1))

    def analyze_packet(self, pkt) -> list[dict] | None:
        if "IP" not in pkt or "TCP" not in pkt:
            return None

        flags = pkt["TCP"].flags

        # Only SYN packets
        if not flags & 0x02:
            return None

        src   = pkt["IP"].src
        dst   = pkt["IP"].dst
        dport = pkt["TCP"].dport
        now   = time.time()

        self._refresh_baselines_if_stale(now)

        # ---- Hard tripwire: high RST/timeout failure rate ----
        # The tripwire is gated by a per-source cooldown so that a sustained
        # scanner doesn't flood the alert pipeline with one HIGH alert per SYN.
        stats      = self.connection_tracker.get_host_stats(src, now)
        total_syns = self.connection_tracker._syn_count(src, now)
        failed_connection_ratio = stats["failed_connection_ratio"]

        if (
            total_syns >= HARD_TRIP_MIN_SYNS
            and failed_connection_ratio > 0.80
        ):
            last_trip = self._last_hard_trip_ts.get(src, 0.0)
            if now - last_trip >= HARD_TRIP_COOLDOWN:
                self._last_hard_trip_ts[src] = now
                msg = f"HIGH FAILURE RATE: {src}"
                return [{
                    "src":       src,
                    "type":      "port_scan",
                    "metric":    "hard_tripwire",
                    "severity":  "HIGH",
                    "message":   msg,
                    "timestamp": int(now),
                }]


        alerts = []

        # ---- Vertical port scan ----
        vkey = (src, dst)

        if vkey not in self.vertical_scan:
            self.vertical_scan[vkey] = {"ports": set(), "time": now}

        self.vertical_scan[vkey]["ports"].add(dport)

        if (
            len(self.vertical_scan[vkey]["ports"]) >= self._get_vertical_threshold(src, now)
            and now - self.vertical_scan[vkey]["time"] <= self.SCAN_WINDOW
        ):
            msg = f"VERTICAL SCAN: {src} → {dst}"
            alerts.append({
                "src":       src,
                "type":      "port_scan",
                "metric":    "vertical",
                "severity":  "HIGH",
                "message":   msg,
                "timestamp": int(now),
            })
            # Reset the port set after alerting so that continued scanning
            # beyond the threshold generates follow-up alerts.
            del self.vertical_scan[vkey]

        # ---- Horizontal port scan ----
        hkey = (src, dport)

        if hkey not in self.horizontal_scan:
            self.horizontal_scan[hkey] = {"hosts": set(), "time": now}

        self.horizontal_scan[hkey]["hosts"].add(dst)

        # Snapshot the set reference once to avoid TOCTOU.
        static_ports = self.static_threshold_ports
        apply_penalty = dport not in static_ports
        h_thresh = self._get_horizontal_threshold(src, now, apply_penalty=apply_penalty)

        if (
            len(self.horizontal_scan[hkey]["hosts"]) >= h_thresh
            and now - self.horizontal_scan[hkey]["time"] <= self.SCAN_WINDOW
        ):
            msg = f"HORIZONTAL SCAN: {src} on port {dport}"
            alerts.append({
                "src":       src,
                "type":      "port_scan",
                "metric":    "horizontal",
                "severity":  "HIGH",
                "message":   msg,
                "timestamp": int(now),
            })
            del self.horizontal_scan[hkey]

        # Throttled cleanup
        if now - self._last_cleanup >= CLEANUP_INTERVAL:
            self.cleanup(now)
            self._last_cleanup = now

        return alerts if alerts else None

    def cleanup(self, now: float) -> None:
        for k in list(self.vertical_scan.keys()):
            if now - self.vertical_scan[k]["time"] > self.SCAN_WINDOW:
                del self.vertical_scan[k]

        for k in list(self.horizontal_scan.keys()):
            if now - self.horizontal_scan[k]["time"] > self.SCAN_WINDOW:
                del self.horizontal_scan[k]

        # Evict stale hard-tripwire cooldown entries to prevent unbounded growth.
        for src in list(self._last_hard_trip_ts.keys()):
            if now - self._last_hard_trip_ts[src] > HARD_TRIP_COOLDOWN:
                del self._last_hard_trip_ts[src]